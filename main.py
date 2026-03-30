import os
from collections import deque
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

# Real-time Genuine Metrics (No dummy data)
performance_stats = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total_scanned": 0}

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
# TRAFFIC INGESTION & ANALYTICS LOGIC
# ──────────────────────────────────────────────
@app.post("/api/agent/traffic")
async def receive_kali_traffic(request: Request):
    try:
        raw_packet = await request.json()
        result = process_live_kali_packet(app.state.clf, app.state.encoder, raw_packet)

        # GENUINE METRICS UPDATE
        # Logic: If prediction is THREAT (1) and we know it's a real attack (is_attack), it's a True Positive.
        pred_val = 1 if result.get("prediction") == "THREAT" else 0
        is_real_attack = raw_packet.get("is_attack", False) # Kali can send this flag for calibration
        
        performance_stats["total_scanned"] += 1
        if pred_val == 1 and is_real_attack: performance_stats["tp"] += 1
        elif pred_val == 1 and not is_real_attack: performance_stats["fp"] += 1
        elif pred_val == 0 and not is_real_attack: performance_stats["tn"] += 1
        elif pred_val == 0 and is_real_attack: performance_stats["fn"] += 1

        traffic_log.appendleft({
            "timestamp": result.get("timestamp", datetime.now().strftime("%H:%M:%S")),
            "source_ip": result.get("source_ip", "0.0.0.0"),
            "protocol": result.get("protocol_type", "TCP").upper(),
            "prediction": result.get("prediction", "NORMAL"),
            "attack_label": result.get("attack_label", "Normal Traffic"),
        })

        await manager.broadcast(result)
        return {"status": "processed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
        "confusion_matrix": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn
        }
    }

@app.get("/api/analytics/features")
async def get_analytics_features():
    # Provide top 10 real feature importances from the loaded XGBoost model
    try:
        from network_monitor import NSL_FEATURES
        clf = app.state.clf
        
        # XGBoost feature importances
        importances = clf.feature_importances_
        
        # Zip with feature names, sort by importance descending
        feat_imp = sorted(zip(NSL_FEATURES, importances), key=lambda x: x[1], reverse=True)
        
        # Return top 10
        top_10 = [{"feature": name, "importance": float(imp)} for name, imp in feat_imp[:10]]
        return top_10
    except Exception as e:
        print(f"[Error] Failed to get feature importances: {e}")
        return []


# ──────────────────────────────────────────────
# DASHBOARD & RULES (SAME AS YOUR ORIGINAL)
# ──────────────────────────────────────────────
@app.get("/api/reports/export")
async def export_report():
    import csv
    import io
    from datetime import datetime
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write Header and Metrics
    writer.writerow(["=== COMMAND ARCHITECT NIDS REPORT ==="])
    writer.writerow(["Generated At:", datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])
    
    tp, tn, fp, fn = performance_stats["tp"], performance_stats["tn"], performance_stats["fp"], performance_stats["fn"]
    total = performance_stats["total_scanned"]
    
    accuracy = ((tp + tn) / total * 100) if total > 0 else 0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    writer.writerow(["--- PERFORMANCE METRICS ---"])
    writer.writerow(["Metric", "Value"])
    writer.writerow(["Total Scanned", total])
    writer.writerow(["True Positives", tp])
    writer.writerow(["False Positives", fp])
    writer.writerow(["True Negatives", tn])
    writer.writerow(["False Negatives", fn])
    writer.writerow(["Accuracy", f"{accuracy:.2f}%"])
    writer.writerow(["Precision", f"{precision:.2f}%"])
    writer.writerow(["Recall", f"{recall:.2f}%"])
    writer.writerow(["F1-Score", f"{f1:.2f}%"])
    writer.writerow([])
    
    # Write Logs
    writer.writerow(["--- RECENT TRAFFIC LOGS ---"])
    if not traffic_log:
        writer.writerow(["No logs captured yet."])
    else:
        writer.writerow(["Timestamp", "Source IP", "Protocol", "Prediction", "Attack Label"])
        for log in traffic_log:
            writer.writerow([
                log.get("timestamp", ""),
                log.get("source_ip", ""),
                log.get("protocol", ""),
                log.get("prediction", ""),
                log.get("attack_label", "")
            ])

    headers = {
        "Content-Disposition": f"attachment; filename=NIDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    }
    return Response(content=output.getvalue(), media_type="text/csv", headers=headers)

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return FileResponse(os.path.join(STATIC_DIR, "code.html"))

@app.get("/api/agent/commands")
async def get_commands():
    return {"banned_ips": list(active_kill_list)}

@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)