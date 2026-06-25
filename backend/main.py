import os
import time
import json
import shutil
from typing import List, Dict
from fastapi import FastAPI, File, UploadFile, Header, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ihealth import iHealthClient

app = FastAPI(
    title="F5 iHealth Watcher API",
    description="Backend API to manage, automate, and visualize F5 QKView diagnostics.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration & Paths
DB_DIR = os.path.join(os.path.dirname(__file__), "database")
DEVICES_FILE = os.path.join(DB_DIR, "devices.json")
os.makedirs(DB_DIR, exist_ok=True)

# iHealth API Credentials (Configure via environment variables or settings)
CLIENT_ID = os.getenv("F5_IHEALTH_CLIENT_ID", "YOUR_CLIENT_ID")
CLIENT_SECRET = os.getenv("F5_IHEALTH_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
TRANSIT_TOKEN = os.getenv("TRANSIT_TOKEN", "your_secure_transit_token")

# Initialize iHealth client
ihealth_client = iHealthClient(CLIENT_ID, CLIENT_SECRET)

# Helper: Load devices registry
def load_devices() -> Dict:
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

# Helper: Save devices registry
def save_devices(devices: Dict):
    with open(DEVICES_FILE, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=4, ensure_ascii=False)

# Background Task to process QKView in iHealth API
def process_qkview_task(file_path: str, hostname: str):
    try:
        # 1. Upload to iHealth
        qkview_id = ihealth_client.upload_qkview(file_path)
        
        # 2. Poll for completion (interval 15s, max 40 attempts = 10 mins)
        success = False
        for _ in range(40):
            status = ihealth_client.check_status(qkview_id)
            if status in ["complete", "finished", "analyzed"]:
                success = True
                break
            elif status in ["failed", "error"]:
                break
            time.sleep(15)
            
        if not success:
            print(f"[{hostname}] iHealth analysis failed or timed out.")
            return

        # 3. Download diagnostics
        diagnostics = ihealth_client.get_diagnostics(qkview_id)
        
        # 4. Parse severity counts and calculate health score
        # iHealth JSON usually contains an array of diagnostic hits
        hits = diagnostics.get("diagnostic_results", {}).get("diagnostic_result", [])
        if not isinstance(hits, list):
            hits = [hits] if hits else []
            
        critical_count = 0
        warning_count = 0
        info_count = 0
        cve_count = 0
        
        for hit in hits:
            severity = hit.get("severity", "").lower()
            if severity == "critical":
                critical_count += 1
            elif severity == "warning":
                warning_count += 1
            elif severity == "info":
                info_count += 1
                
            # Check if there is a CVE associated
            if hit.get("cve") or "cve-" in str(hit.get("title", "")).lower():
                cve_count += 1

        # Calculate custom health score: starting at 100
        # Deduct 12 points for criticals, 4 points for warnings
        health_score = max(30, 100 - (critical_count * 12) - (warning_count * 4))
        
        # 5. Save diagnostic results JSON
        device_diag_file = os.path.join(DB_DIR, f"{hostname}_diagnostics.json")
        with open(device_diag_file, "w", encoding="utf-8") as f:
            json.dump(diagnostics, f, indent=4, ensure_ascii=False)
            
        # 6. Update devices registry
        devices = load_devices()
        devices[hostname] = {
            "hostname": hostname,
            "last_scan": time.strftime("%Y-%m-%d %H:%M:%S"),
            "health_score": health_score,
            "stats": {
                "critical": critical_count,
                "warning": warning_count,
                "info": info_count,
                "cves": cve_count
            }
        }
        save_devices(devices)
        print(f"[{hostname}] iHealth diagnostic completed and saved successfully.")

    except Exception as e:
        print(f"Error processing QKView for {hostname}: {e}")
    finally:
        # Cleanup temporary uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)

# Endpoints
@app.post("/api/upload", summary="Upload QKView from F5 BIG-IP")
async def upload_qkview(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    authorization: str = Header(None)
):
    # Validate Transit Token
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    
    token = authorization.split(" ")[1]
    if token != TRANSIT_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid transit token.")
        
    # Extract hostname from filename (format: hostname_timestamp.qkview)
    filename = file.filename
    hostname = "unknown-f5"
    if "_" in filename:
        hostname = filename.split("_")[0]
    elif ".qkview" in filename:
        hostname = filename.replace(".qkview", "")

    # Save uploaded file temporarily
    temp_file_path = os.path.join(DB_DIR, f"temp_{int(time.time())}_{filename}")
    with open(temp_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # Queue the iHealth API upload and processing as a background task
    background_tasks.add_task(process_qkview_task, temp_file_path, hostname)
    
    return JSONResponse(
        status_code=202,
        content={
            "message": "QKView received successfully. Diagnostic processing started in background.",
            "hostname": hostname,
            "filename": filename
        }
    )

@app.get("/api/devices", summary="Get list of all monitored F5 devices")
async def get_devices():
    devices = load_devices()
    return list(devices.values())

@app.get("/api/diagnostics/{hostname}", summary="Get latest diagnostic report for a device")
async def get_diagnostics(hostname: str):
    device_diag_file = os.path.join(DB_DIR, f"{hostname}_diagnostics.json")
    if not os.path.exists(device_diag_file):
        raise HTTPException(status_code=404, detail=f"No diagnostic report found for device '{hostname}'.")
        
    with open(device_diag_file, "r", encoding="utf-8") as f:
        return json.load(f)

# Health Check
@app.get("/health")
async def health():
    return {"status": "healthy", "time": time.time()}

# Mount static frontend files
# When deployed on Railway with root directory '/backend', the frontend is at '../frontend'
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
