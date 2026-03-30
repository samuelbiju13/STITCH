"""
network_monitor.py - Live Traffic Simulation & Real-Time ML Inference (NSL-KDD Edition)
=========================================================================================
Simulates live network packet events whose features align with the NSL-KDD dataset schema
(42 features per packet). Each simulated packet is preprocessed using the saved
LabelEncoder dict and fed into the trained Random Forest model for real-time prediction.

In production you would replace generate_live_packet() with Scapy capture and extract
the same 42 NSL-KDD features from the raw packet headers and connection statistics.
"""

import asyncio
import random
import time
import numpy as np
import pandas as pd
from collections import deque

# Memory buffer to track recent IPs for DoS detection
recent_ips = deque(maxlen=1000)

from ml_pipeline import load_model, preprocess, CATEGORICAL_COLS, TARGET_COL

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# ──────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────
EMIT_INTERVAL_SECONDS   = 0.35   # ~2.8 packets/sec
ANOMALY_PROBABILITY     = 0.22   # ~22% of generated packets show anomaly patterns
LOG_CONFIDENCE_THRESHOLD = 0.55  # Min confidence to add a row to the threat log

# Human-readable threat labels mapped to anomaly-biased port-like service names
ATTACK_LABELS = {
    "private":     "Port Scan",
    "telnet":      "SSH Brute Force",
    "ftp_data":    "FTP Data Exfil",
    "imap4":       "Mail Exploit",
    "smtp":        "SMTP Attack",
    "pop_3":       "POP3 Probe",
    "ecr_i":       "ICMP Flood",
    "eco_i":       "ICMP Sweep",
    "http":        "HTTP Flood",
    "ftp":         "FTP Brute Force",
    "auth":        "Auth Exploit",
    "netbios_dgm": "NetBIOS Exploit",
    "domain":      "DNS Amplification",
}
NORMAL_LABEL = "Normal Traffic"

# Pools for simulated source IPs (for the UI display only — not a model feature)
NORMAL_IPS = [
    "10.0.0.1", "10.0.0.22", "192.168.1.10", "192.168.1.55",
    "172.16.0.14", "10.0.1.200", "192.168.0.3",
]
SUSPECT_IPS = [
    "45.22.190.11", "182.54.12.9", "91.108.4.202", "66.220.3.11",
    "203.0.113.42", "198.51.100.7", "185.220.101.5",
]


# ──────────────────────────────────────────────────────────────
# NSL-KDD FEATURE SCHEMA
# These are the 42 feature columns (minus 'class') in order.
# We'll generate plausible values for each.
# ──────────────────────────────────────────────────────────────
NSL_FEATURES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]


def generate_live_packet(is_anomaly: bool) -> dict:
    """
    Fabricates one NSL-KDD-style packet feature dict.

    Normal traffic profile:
        - Short duration, small src_bytes, SF flag, common services (http, smtp, ftp)
        - Logged in, low error rates, high same_srv_rate

    Anomaly traffic profile:
        - Long duration or zero, large src_bytes, REJ/S0/RSTO flags
        - Private/telnet/imap4 services, high error rates

    Returns a dict with all 42 NSL-KDD features plus:
        - source_ip : str  (for display in the threat log)
        - service   : str  (used to look up the human-readable attack label)
    """
    if is_anomaly:
        src_ip      = random.choice(SUSPECT_IPS)
        protocol    = random.choice(["tcp", "icmp", "tcp"])   # TCP-heavy anomalies
        service     = random.choice(["private", "telnet", "ecr_i", "eco_i",
                                     "imap4", "ftp_data", "netbios_dgm", "domain", "ftp"])
        flag        = random.choice(["REJ", "S0", "RSTO", "RSTOS0", "SH"])
        duration    = random.choice([0, 0, 0, random.randint(100, 8000)])
        src_bytes   = random.choice([0, 0, random.randint(5000, 65535)])
        dst_bytes   = 0
        land        = "0"
        wrong_frag  = random.choice([0, 0, 1])
        logged_in   = "0"
        hot         = random.randint(0, 4)
        serror_rate = round(random.uniform(0.7, 1.0), 2)
        rerror_rate = round(random.uniform(0.7, 1.0), 2)
        same_srv    = round(random.uniform(0.0, 0.3), 2)
        diff_srv    = round(random.uniform(0.06, 0.2), 2)
        count       = random.randint(100, 511)
        srv_count   = random.randint(1, 30)
        dst_count   = random.choice([255, random.randint(50, 255)])
    else:
        src_ip      = random.choice(NORMAL_IPS)
        protocol    = random.choice(["tcp", "udp"])
        service     = random.choice(["http", "smtp", "ftp_data", "domain_u",
                                     "pop_3", "auth", "ftp", "finger"])
        flag        = "SF"
        duration    = random.randint(0, 60)
        src_bytes   = random.randint(100, 5000)
        dst_bytes   = random.randint(100, 20000)
        land        = "0"
        wrong_frag  = 0
        logged_in   = "1"
        hot         = random.randint(0, 5)
        serror_rate = 0.0
        rerror_rate = 0.0
        same_srv    = round(random.uniform(0.85, 1.0), 2)
        diff_srv    = round(random.uniform(0.0, 0.05), 2)
        count       = random.randint(1, 60)
        srv_count   = random.randint(1, 30)
        dst_count   = random.choice([255, random.randint(50, 255)])

    return {
        # 42 NSL-KDD features
        "duration":                    duration,
        "protocol_type":               protocol,
        "service":                     service,
        "flag":                        flag,
        "src_bytes":                   src_bytes,
        "dst_bytes":                   dst_bytes,
        "land":                        land,
        "wrong_fragment":              wrong_frag,
        "urgent":                      0,
        "hot":                         hot,
        "num_failed_logins":           0,
        "logged_in":                   logged_in,
        "num_compromised":             0,
        "root_shell":                  0,
        "su_attempted":                0,
        "num_root":                    0,
        "num_file_creations":          0,
        "num_shells":                  0,
        "num_access_files":            0,
        "num_outbound_cmds":           0,
        "is_host_login":               "0",
        "is_guest_login":              "0",
        "count":                       count,
        "srv_count":                   srv_count,
        "serror_rate":                 serror_rate,
        "srv_serror_rate":             serror_rate,
        "rerror_rate":                 rerror_rate,
        "srv_rerror_rate":             rerror_rate,
        "same_srv_rate":               same_srv,
        "diff_srv_rate":               diff_srv,
        "srv_diff_host_rate":          round(random.uniform(0.0, 0.3), 2),
        "dst_host_count":              dst_count,
        "dst_host_srv_count":          random.randint(1, 255),
        "dst_host_same_srv_rate":      same_srv,
        "dst_host_diff_srv_rate":      diff_srv,
        "dst_host_same_src_port_rate": round(random.uniform(0.0, 1.0), 2),
        "dst_host_srv_diff_host_rate": round(random.uniform(0.0, 0.3), 2),
        "dst_host_serror_rate":        serror_rate,
        "dst_host_srv_serror_rate":    serror_rate,
        "dst_host_rerror_rate":        rerror_rate,
        "dst_host_srv_rerror_rate":    rerror_rate,
        # UI metadata (not fed to the model)
        "source_ip":                   src_ip,
    }


# ──────────────────────────────────────────────────────────────
# INFERENCE ENGINE
# ──────────────────────────────────────────────────────────────
def predict_packet(clf, encoders: dict, packet: dict) -> dict:
    """
    Runs one NSL-KDD feature dict through the trained Random Forest classifier.

    The encoders argument is now a dict {col_name: LabelEncoder} as produced
    by the updated ml_pipeline.py. We build a single-row DataFrame with the
    42 feature columns, pass it through preprocess() in inference mode
    (fit=False), and return the prediction result.

    Returns:
        A dict with all original packet keys PLUS:
            prediction   : "NORMAL" | "THREAT"
            confidence   : float 0.0–1.0
            attack_label : human-readable classification
            timestamp    : "HH:MM:SS.mmm"
            target_port  : int (derived from service mapping for UI display)
            log_it       : bool — True when threat with high enough confidence
    """
    # Build single-row DataFrame (42 feature columns only, drop source_ip)
    feature_dict = {k: v for k, v in packet.items() if k != "source_ip"}
    df_row = pd.DataFrame([feature_dict])

    # Preprocess in inference mode — applies saved label encoders
    X, _, _ = preprocess(df_row, encoders=encoders, fit=False)

    # Model prediction
    predicted_class = int(clf.predict(X)[0])        # 0=normal, 1=anomaly
    proba           = clf.predict_proba(X)[0]        # [P(normal), P(anomaly)]
    confidence      = float(proba[predicted_class])

    prediction_str = "THREAT" if predicted_class == 1 else "NORMAL"
    attack_label   = (
        ATTACK_LABELS.get(packet.get("service", ""), "Intrusion Detected")
        if predicted_class == 1
        else NORMAL_LABEL
    )

    reasoning = []
    if predicted_class == 1:
        # XAI locally-weighted feature importance
        weighted_features = X[0] * clf.feature_importances_
        top_indices = np.argsort(weighted_features)[-3:][::-1]
        
        FEATURE_REASONS = {
            "src_bytes": "Abnormal Payload Size",
            "dst_bytes": "Unexpected Data Transfer",
            "count": "Suspicious Connection Count",
            "diff_srv_rate": "High Service Churn",
            "same_srv_rate": "Unusual Service Targeting",
            "dst_host_srv_count": "Target Saturation",
            "dst_host_diff_srv_rate": "Distributed Port Sweep",
            "flag": "Abnormal TCP Flags",
            "duration": "Extended Connection Time",
            "service": "Unusual Network Service",
            "protocol_type": "Unexpected Protocol",
            "wrong_fragment": "Fragmented Packet Attack",
            "hot": "System Hotspots Targeted",
            "num_failed_logins": "Multiple Failed Logins",
            "srv_count": "Rapid Service Requests",
            "serror_rate": "High SYN Error Rate",
            "rerror_rate": "High REJ Error Rate",
            "dst_host_same_srv_rate": "Targeted Service Flood",
            "dst_host_serror_rate": "Destination SYN Errors"
        }
        
        for idx in top_indices:
            feat_name = NSL_FEATURES[idx]
            reasoning.append(FEATURE_REASONS.get(feat_name, f"Anomalous {feat_name}"))

    # Map service name to a display port number for the Threat Log UI column
    SERVICE_PORT_MAP = {
        "http": 80, "smtp": 25, "ftp": 21, "ftp_data": 20,
        "domain": 53, "domain_u": 53, "telnet": 23, "ssh": 22,
        "pop_3": 110, "imap4": 143, "auth": 113, "ecr_i": 0,
        "eco_i": 0, "private": random.randint(1024, 65535),
        "netbios_dgm": 138, "netbios_ns": 137,
    }
    target_port = SERVICE_PORT_MAP.get(packet.get("service", ""), 0)

    now     = time.time()
    millis  = int((now % 1) * 1000)
    ts      = time.strftime(f"%H:%M:%S.{millis:03d}")

    return {
        **packet,
        "target_port": target_port,
        "prediction":  prediction_str,
        "confidence":  round(confidence, 4),
        "attack_label": attack_label,
        "timestamp":   ts,
        "log_it": predicted_class == 1 and confidence >= LOG_CONFIDENCE_THRESHOLD,
        "reasoning":   reasoning,
    }


# ──────────────────────────────────────────────────────────────
# ASYNC STREAM GENERATOR
# ──────────────────────────────────────────────────────────────
async def traffic_stream(clf, encoders):
    """
    Async generator yielding one prediction dict every ~EMIT_INTERVAL_SECONDS.

    Usage in FastAPI WebSocket handler:
        async for packet in traffic_stream(clf, encoders):
            await ws.send_json(packet)
    """
    while True:
        is_anomaly  = random.random() < ANOMALY_PROBABILITY
        raw_packet  = generate_live_packet(is_anomaly)
        result      = predict_packet(clf, encoders, raw_packet)
        yield result
        await asyncio.sleep(random.uniform(0.30, 0.50))

# ──────────────────────────────────────────────────────────────
# LIVE KALI INFERENCE BRIDGE
# ──────────────────────────────────────────────────────────────
def process_live_kali_packet(clf, encoders, raw_packet: dict) -> dict:
    """
    Takes a raw packet from Kali (e.g., {"src_ip": "192.168.1.39", "proto": "tcp", "size": 60})
    and translates it into the full 42-feature NSL-KDD schema before prediction.
    """
    src_ip = raw_packet.get("src_ip", "0.0.0.0")
    recent_ips.append(src_ip)
    
    # Calculate volume for DoS/Flood detection
    packet_count = recent_ips.count(src_ip)

    # Extract raw Kali features
    protocol = raw_packet.get("proto", "tcp").lower()
    size = raw_packet.get("size", 0)
    port = raw_packet.get("port", 0)

    # Intelligent Service Mapping based on Port
    if port in [80, 443]: service = "http"
    elif port == 53: service = "domain"
    elif port == 21: service = "ftp"
    elif port == 22: service = "ssh"
    else: service = "private"

    # Build the 42-feature NSL-KDD synthetic mapping
    nsl_packet = {
        "duration": 0, "protocol_type": protocol, "service": service, "flag": "SF",
        "src_bytes": size, "dst_bytes": 0, "land": "0", "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": "0",
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": "0", "is_guest_login": "0",
        "count": packet_count, "srv_count": packet_count, # The DoS triggers
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0, "dst_host_count": 255, "dst_host_srv_count": 255,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
        "source_ip": src_ip # Kept for the UI Threat Log
    }

    # Pass the synthesized 42-feature packet into your existing engine
    return predict_packet(clf, encoders, nsl_packet)