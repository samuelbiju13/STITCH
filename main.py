import os
from collections import deque, Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

# Internal STITCH Modules
from ml_pipeline import load_model
from network_monitor import process_live_kali_packet 

# ──────────────────────────────────────────────
# STATE & CONFIGURATION
# ──────────────────────────────────────────────
active_kill_list = set()
active_rules = []
_rule_counter = 0
traffic_log = deque(maxlen=100)

# Real-time Genuine Metrics
performance_stats = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total_scanned": 0}

# Global Settings State
current_settings = {
    "confidence_threshold": 85,
    "auto_block": False,
    "audio_alerts": False
}

class DeployRuleRequest(BaseModel):
    target_ip: str
    action: str

class SettingsRequest(BaseModel):
    confidence_threshold: int
    auto_block: bool
    audio_alerts: bool

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.append(ws)
    def disconnect(self, ws: WebSocket):
        if ws in self.active_connections: self.active_connections.remove(ws)
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

# ──────────────────────────────────────────────
# LIFESPAN & APP INIT
# ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[main] Loading XGBoost ML model...")
    app.state.clf, app.state.encoder = load_model()
    print("[main] STITCH Command Center is live.")
    yield
    print("[main] Server shutting down.")

app = FastAPI(title="COMMAND_ARCHITECT_NIDS", lifespan=lifespan)
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

# ──────────────────────────────────────────────
# CORE TRAFFIC INGESTION
# ──────────────────────────────────────────────
@app.post("/api/agent/traffic")
async def receive_kali_traffic(request: Request):
    try:
        raw_packet = await request.json()
        result = process_live_kali_packet(app.state.clf, app.state.encoder, raw_packet)

        pred_val = 1 if result.get("prediction") == "THREAT" else 0
        is_real_attack = raw_packet.get("is_attack", False) 
        
        performance_stats["total_scanned"] += 1
        if pred_val == 1 and is_real_attack: performance_stats["tp"] += 1
        elif pred_val == 1 and not is_real_attack: performance_stats["fp"] += 1
        elif pred_val == 0 and not is_real_attack: performance_stats["tn"] += 1
        elif pred_val == 0 and is_real_attack: performance_stats["fn"] += 1

        log_entry = {
            "timestamp": result.get("timestamp", datetime.now().strftime("%H:%M:%S")),
            "source_ip": result.get("source_ip", "0.0.0.0"),
            "protocol": result.get("protocol_type", "TCP").upper(),
            "target_port": result.get("target_port", 0),
            "prediction": result.get("prediction", "NORMAL"),
            "confidence": result.get("confidence", 0),
            "attack_label": result.get("attack_label", "Normal Traffic"),
            "log_it": True
        }
        traffic_log.appendleft(log_entry)

        await manager.broadcast(log_entry)
        return {"status": "processed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ──────────────────────────────────────────────
# ANALYTICS & DASHBOARD ENDPOINTS
# ──────────────────────────────────────────────
@app.get("/health")
async def health_check():
    return {"status": "online"}

@app.get("/api/nodes")
async def get_nodes():
    return [{
        "node_id": "NODE_01_PROXIMITY",
        "ip_address": "192.168.0.102",
        "os_kernel": "Kali GNU/Linux",
        "latency": "12ms",
        "uptime": "Active"
    }]

@app.get("/api/analytics/top-threats")
async def get_top_threats():
    threat_counts = Counter([log["source_ip"] for log in traffic_log if log["prediction"] == "THREAT"])
    return [{"ip": ip, "hits": count} for ip, count in threat_counts.most_common(5)]

@app.get("/api/analytics/metrics")
async def get_analytics_metrics():
    tp, tn, fp, fn = performance_stats["tp"], performance_stats["tn"], performance_stats["fp"], performance_stats["fn"]
    total = performance_stats["total_scanned"]
    
    accuracy = ((tp + tn) / total * 100) if total > 0 else 0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    return {
        "accuracy": f"{accuracy:.2f}",
        "precision": f"{precision:.2f}",
        "recall": f"{recall:.2f}",
        "f1_score": f"{f1:.2f}",
        "threats_caught": tp,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
    }

@app.get("/api/analytics/features")
async def get_analytics_features():
    try:
        from network_monitor import NSL_FEATURES
        clf = app.state.clf
        importances = clf.feature_importances_
        feat_imp = sorted(zip(NSL_FEATURES, importances), key=lambda x: x[1], reverse=True)
        return [{"feature": name, "importance": float(imp)} for name, imp in feat_imp[:10]]
    except Exception as e:
        return []

@app.get("/api/logs")
async def get_logs():
    return {"logs": list(traffic_log)}

# ──────────────────────────────────────────────
# ACTIVE DEFENSE & SETTINGS
# ──────────────────────────────────────────────
@app.post("/api/rules/deploy", status_code=201)
async def deploy_rule(payload: DeployRuleRequest):
    global _rule_counter
    ip = payload.target_ip.strip()
    action = payload.action.strip()

    if not ip: raise HTTPException(status_code=422, detail="target_ip must not be empty")

    if action == "Block":
        active_kill_list.add(ip)
    
    _rule_counter += 1
    rule = {
        "id": _rule_counter, "ip": ip, "action": action,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    active_rules.insert(0, rule)
    return {"status": "deployed", "rule": rule}

@app.get("/api/rules")
async def list_rules(): return {"rules": active_rules}

@app.delete("/api/rules/{rule_id}")
async def revoke_rule(rule_id: int):
    global active_rules
    for i, rule in enumerate(active_rules):
        if rule["id"] == rule_id:
            removed = active_rules.pop(i)
            if removed['ip'] in active_kill_list:
                active_kill_list.remove(removed['ip'])
            return {"status": "revoked", "rule_id": rule_id}
    raise HTTPException(status_code=404, detail="Rule not found")

@app.get("/api/settings")
async def get_settings():
    return current_settings

@app.post("/api/settings")
async def update_settings(settings: SettingsRequest):
    global current_settings
    current_settings.update(settings.dict())
    return {"status": "success", "settings": current_settings}

@app.get("/api/agent/commands")
async def get_commands():
    return {"banned_ips": list(active_kill_list)}

# ──────────────────────────────────────────────
# REPORTS & WEBSOCKET
# ──────────────────────────────────────────────
@app.get("/api/reports/export")
async def export_report():
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["=== COMMAND ARCHITECT NIDS REPORT ==="])
    writer.writerow(["Generated At:", datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])
    
    tp, tn, fp, fn = performance_stats["tp"], performance_stats["tn"], performance_stats["fp"], performance_stats["fn"]
    total = performance_stats["total_scanned"]
    
    accuracy = ((tp + tn) / total * 100) if total > 0 else 0
    writer.writerow(["--- PERFORMANCE METRICS ---"])
    writer.writerow(["Total Scanned", total])
    writer.writerow(["Accuracy", f"{accuracy:.2f}%"])
    writer.writerow([])
    
    writer.writerow(["--- RECENT TRAFFIC LOGS ---"])
    if not traffic_log:
        writer.writerow(["No logs captured yet."])
    else:
        writer.writerow(["Timestamp", "Source IP", "Protocol", "Prediction", "Attack Label"])
        for log in traffic_log:
            writer.writerow([log.get("timestamp", ""), log.get("source_ip", ""), log.get("protocol", ""), log.get("prediction", ""), log.get("attack_label", "")])

    headers = {"Content-Disposition": f"attachment; filename=NIDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    return Response(content=output.getvalue(), media_type="text/csv", headers=headers)

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return FileResponse(os.path.join(STATIC_DIR, "code.html"))

@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)