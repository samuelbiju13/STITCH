# 🛡️ STITCH: Distributed AI Network Intrusion Prevention System

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Next.js](https://img.shields.io/badge/Next.js-14-black.svg)
![XGBoost](https://img.shields.io/badge/XGBoost-Machine%20Learning-orange.svg)
![Kali Linux](https://img.shields.io/badge/Kali-Sensor%20Node-blueviolet.svg)

**STITCH** is a distributed, AI-powered Network Intrusion Prevention System (NIPS) engineered for sub-200ms threat mitigation. It decouples low-level packet enforcement from heavy machine learning inference, allowing for real-time, stateful evaluation of network traffic without bottlenecking edge routing.

## 🏗️ System Architecture

Traditional cloud-based AI security suffers from latency, while signature-based NIDS fails against zero-day exploits. STITCH solves this via a 3-tier distributed topology:

1. **The Sensor Node (Kali Linux):** A lightweight Man-in-the-Middle (MitM) agent utilizing ARP spoofing to intercept bidirectional traffic and `iptables` for automated active defense.
2. **The Intelligence Core (FastAPI & XGBoost):** An asynchronous Python backend that ingests raw telemetry, calculates packet velocity, and executes XGBoost classification.
3. **The Command Center (Next.js):** A WebSocket-driven frontend providing zero-latency visual analytics and live threat logs.

## ✨ Key Engineering Features

* **Stateful Velocity Tracking:** Resolves the "Training-Serving Skew" inherent in models trained on the NSL-KDD dataset. It translates stateless packets into stateful flows (PPS monitoring, dynamic `S0` flag injection) to catch volumetric attacks like TCP SYN Floods that mimic normal traffic.
* **Automated Active Defense:** Bypasses manual administration. Upon >95% threat confidence, the AI autonomously pushes an IP-specific `iptables` drop rule to the Kali sensor.
* **Sub-200ms Mitigation:** By utilizing XGBoost over heavier Deep Learning models (LSTMs), STITCH performs instantaneous tabular inference at the network edge.

## 🚀 Quick Start / Deployment

### 1. Initialize the Intelligence Core (Windows/Host)
git clone https://github.com/yourusername/stitch.git
cd stitch/backend
pip install -r requirements.txt
python main.py
*The command center will be available at `http://localhost:8000`.*

### 2. Deploy the Sensor (Kali Linux VM/Node)
cd stitch/agent
chmod +x launch_stitch.sh
sudo ./launch_stitch.sh
*Provide the target IP address when prompted to initialize the MitM intercept.*

## 🔬 Testing the Defense
To validate the model, run a synthetic stress test from a separate Kali terminal against the monitored target:

# TCP SYN Flood (Resource Exhaustion)
sudo hping3 -S -p 80 --flood <TARGET_IP>

# Aggressive Reconnaissance (Stealth Scan)
sudo nmap -sS -T4 -A <TARGET_IP>

---
**Author:** Samuel Biju  
**Institution:** Christ University (B.Tech CSE - AIML)  
**Track:** Honors in Cybersecurity & Ethical Hacking
