import time
import requests
import platform
import socket
import random

# Point this to your FastAPI server
SERVER_URL = "http://localhost:8000/api/nodes/heartbeat"

# Give this specific machine a name
NODE_ID = "NODE_01_COMMAND_HOST"

def get_local_ip():
    """Dynamically grabs the active local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable, just forces the socket to resolve local IP
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def send_heartbeat():
    """Packages system stats and sends them to the dashboard."""
    payload = {
        "node_id": NODE_ID,
        "ip_address": get_local_ip(),
        "os_kernel": f"{platform.system()} {platform.release()}",
        # Simulating latency for the visual effect
        "latency": f"{random.randint(10, 45)}ms", 
        "uptime": "Active"
    }
    
    try:
        response = requests.post(SERVER_URL, json=payload)
        if response.status_code == 200:
            print(f"[+] Heartbeat sent for {NODE_ID} -> OK")
    except requests.exceptions.ConnectionError:
        print("[-] Server unreachable. Is server.py running? Retrying in 10s...")

if __name__ == "__main__":
    print(f"[*] Starting NIDS Agent: {NODE_ID}")
    print(f"[*] Target Server: {SERVER_URL}")
    print("[*] Press Ctrl+C to stop.\n")
    
    while True:
        send_heartbeat()
        # Sends a ping every 10 seconds
        time.sleep(10)