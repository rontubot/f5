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

# Helper: Resolve iHealth QKView ID from local devices registry or by querying historical uploaded list
def resolve_qkview_id(hostname: str) -> str:
    devices = load_devices()
    dev = devices.get(hostname, {})
    
    # 1. Check if qkview_id is already in cache
    if "qkview_id" in dev and dev["qkview_id"]:
        return dev["qkview_id"]
        
    # 2. Query historical QKViews list from iHealth API to match the hostname
    try:
        qkviews_data = ihealth_client.get_qkviews_list()
        qkviews = []
        if isinstance(qkviews_data, dict):
            qkview_node = qkviews_data.get("qkview") or qkviews_data.get("qkviews", {}).get("qkview", [])
            qkviews = qkview_node if isinstance(qkview_node, list) else [qkview_node] if qkview_node else []
        elif isinstance(qkviews_data, list):
            qkviews = qkviews_data
            
        for qk in qkviews:
            fname = qk.get("file_name", "") or qk.get("description", "") or ""
            if hostname.lower() in fname.lower():
                qk_id = qk.get("id") or qk.get("qkview_id") or qk.get("qkviewId")
                if qk_id:
                    # Update local registry so we don't list again
                    if hostname not in devices:
                        devices[hostname] = {}
                    devices[hostname]["qkview_id"] = str(qk_id)
                    save_devices(devices)
                    print(f"[resolve_qkview_id] Resolved and saved QKView ID '{qk_id}' for '{hostname}' from F5 list.")
                    return str(qk_id)
    except Exception as e:
        print(f"Error resolving qkview_id for {hostname}: {e}")
        
    return None

# Background Task to process QKView in iHealth API
def process_qkview_task(file_path: str, hostname: str):
    try:
        # 1. Upload to iHealth
        qkview_id = ihealth_client.upload_qkview(file_path)
        
        # 2. Poll for completion (interval 30s, max 60 attempts = 30 mins)
        success = False
        print(f"[Task] Iniciando ciclo de sondeo (polling) en iHealth para {hostname}...")
        for attempt in range(1, 61):
            print(f"[Task] Intento de sondeo {attempt}/60 para el ID: {qkview_id}...")
            status = ihealth_client.check_status(qkview_id)
            if status in ["complete", "completed", "finished", "analyzed", "success", "succeeded"]:
                print(f"[Task] ¡Análisis completado en iHealth en el intento {attempt}!")
                success = True
                break
            elif status in ["failed", "error"]:
                print(f"[Task] ERROR: El estado del análisis en iHealth reporta: '{status}'")
                break
            time.sleep(30)
            
        if not success:
            print(f"[Task] [{hostname}] iHealth analysis failed or timed out.")
            devices = load_devices()
            if hostname in devices:
                devices[hostname]["status"] = "failed"
                devices[hostname]["error_message"] = "El análisis en iHealth falló o superó el tiempo de espera en F5."
                save_devices(devices)
            return

        # 3. Download diagnostics
        print(f"[Task] Descargando el archivo JSON de diagnóstico para {hostname}...")
        diagnostics = ihealth_client.get_diagnostics(qkview_id)
        
        # 4. Parse severity counts and calculate health score
        # The F5 iHealth API structure: diagnostics -> diagnostic -> [list of items]
        diagnostics_node = diagnostics.get("diagnostics", {})
        hits = diagnostics_node.get("diagnostic", [])
        if not isinstance(hits, list):
            hits = [hits] if hits else []
            
        print(f"[Task] Se encontraron {len(hits)} heurísticas totales en el diagnóstico.")
            
        critical_count = 0
        warning_count = 0
        info_count = 0
        cve_count = 0
        
        for hit in hits:
            run_data = hit.get("run_data", {})
            # Solo procesar si la heurística coincide con el estado del F5 (match === True)
            if not run_data.get("match", False):
                continue
                
            results = hit.get("results", {})
            importance = run_data.get("h_importance", "").lower()
            
            # Mapear importancia de F5 a nuestras categorías (HIGH/CRITICAL -> critical, MEDIUM -> warning, LOW/INFO -> info)
            if importance in ["high", "critical"]:
                critical_count += 1
            elif importance == "medium":
                warning_count += 1
            else:
                info_count += 1
                
            # Contar la cantidad de CVEs identificados
            cve_ids = results.get("h_cve_ids", [])
            if cve_ids:
                cve_count += len(cve_ids)

        # Calcular score de salud real (iniciando en 100 y restando peso por alertas)
        # Cada alerta crítica descuenta 10 puntos, cada advertencia descuenta 3 puntos
        health_score = max(30, 100 - (critical_count * 10) - (warning_count * 3))
        print(f"[Task] Estadísticas consolidadas para {hostname}: Críticas={critical_count}, Advertencias={warning_count}, Info={info_count}, CVEs={cve_count}, Score={health_score}")
        
        # 5. Save diagnostic results JSON
        device_diag_file = os.path.join(DB_DIR, f"{hostname}_diagnostics.json")
        with open(device_diag_file, "w", encoding="utf-8") as f:
            json.dump(diagnostics, f, indent=4, ensure_ascii=False)
            
        # 6. Update devices registry
        devices = load_devices()
        devices[hostname] = {
            "hostname": hostname,
            "last_scan": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "completed",
            "health_score": health_score,
            "qkview_id": qkview_id,
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
        try:
            devices = load_devices()
            if hostname in devices:
                devices[hostname]["status"] = "failed"
                devices[hostname]["error_message"] = str(e)
                save_devices(devices)
        except:
            pass
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
        
    # Immediately register/update the device as "processing" in the database
    devices = load_devices()
    devices[hostname] = {
        "hostname": hostname,
        "last_scan": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "processing",
        "health_score": 0,
        "stats": {
            "critical": 0,
            "warning": 0,
            "info": 0,
            "cves": 0
        }
    }
    save_devices(devices)

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

# Endpoints: QKView Files & Commands Logs Explorer
@app.get("/api/devices/{hostname}/files", summary="Get list of files contained in the QKView")
async def get_device_files(hostname: str):
    qkview_id = resolve_qkview_id(hostname)
    if not qkview_id:
        raise HTTPException(status_code=404, detail=f"No se pudo resolver el QKView ID para el dispositivo '{hostname}'.")
    try:
        files_data = ihealth_client.get_qkview_files(qkview_id)
        
        # Normalizar respuesta XML-a-JSON a lista plana de diccionarios
        files_list = []
        if isinstance(files_data, dict):
            file_node = files_data.get("file") or files_data.get("files", {}).get("file", [])
            files_list = file_node if isinstance(file_node, list) else [file_node] if file_node else []
        elif isinstance(files_data, list):
            files_list = files_data
            
        normalized = []
        for f in files_list:
            f_id = f.get("id") or f.get("id_hash") or f.get("hash")
            f_name = f.get("name") or f.get("path") or f.get("file_path") or ""
            if f_id and f_name:
                normalized.append({"id": str(f_id), "name": str(f_name)})
                
        # Ordenar alfabéticamente por nombre
        normalized.sort(key=lambda x: x["name"])
        return normalized
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener archivos de iHealth: {str(e)}")

@app.get("/api/devices/{hostname}/files/{file_id}", summary="Get content of a specific log file in the QKView")
async def get_device_file_content(hostname: str, file_id: str):
    qkview_id = resolve_qkview_id(hostname)
    if not qkview_id:
        raise HTTPException(status_code=404, detail=f"No se pudo resolver el QKView ID para el dispositivo '{hostname}'.")
    try:
        content = ihealth_client.get_qkview_file_content(qkview_id, file_id)
        try:
            text_content = content.decode("utf-8")
        except UnicodeDecodeError:
            text_content = content.decode("latin-1", errors="replace")
        return {"content": text_content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al descargar contenido del archivo: {str(e)}")

@app.get("/api/devices/{hostname}/commands", summary="Get list of TMSH commands executed in the QKView")
async def get_device_commands(hostname: str):
    qkview_id = resolve_qkview_id(hostname)
    if not qkview_id:
        raise HTTPException(status_code=404, detail=f"No se pudo resolver el QKView ID para el dispositivo '{hostname}'.")
    try:
        commands_data = ihealth_client.get_qkview_commands(qkview_id)
        
        # Normalizar respuesta XML-a-JSON a lista plana
        commands_list = []
        if isinstance(commands_data, dict):
            cmd_node = commands_data.get("command") or commands_data.get("commands", {}).get("command", [])
            commands_list = cmd_node if isinstance(cmd_node, list) else [cmd_node] if cmd_node else []
        elif isinstance(commands_data, list):
            commands_list = commands_data
            
        normalized = []
        for c in commands_list:
            c_id = c.get("id") or c.get("id_hash") or c.get("hash")
            c_name = c.get("name") or c.get("command_name") or c.get("command") or ""
            if c_id and c_name:
                normalized.append({"id": str(c_id), "name": str(c_name)})
                
        normalized.sort(key=lambda x: x["name"])
        return normalized
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener comandos de iHealth: {str(e)}")

@app.get("/api/devices/{hostname}/commands/{command_id}", summary="Get content of a specific command output in the QKView")
async def get_device_command_content(hostname: str, command_id: str):
    qkview_id = resolve_qkview_id(hostname)
    if not qkview_id:
        raise HTTPException(status_code=404, detail=f"No se pudo resolver el QKView ID para el dispositivo '{hostname}'.")
    try:
        content = ihealth_client.get_qkview_command_content(qkview_id, command_id)
        try:
            text_content = content.decode("utf-8")
        except UnicodeDecodeError:
            text_content = content.decode("latin-1", errors="replace")
        return {"content": text_content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al descargar contenido del comando: {str(e)}")

# Mount static frontend files
# When deployed on Railway, the frontend is inside the backend directory
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "frontend"))
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
