import os
import time
import base64
import json
import requests

TOKEN_URL = "https://identity.account.f5.com/oauth2/ausp95ykc80HOU7SQ357/v1/token"
API_BASE_URL = "https://ihealth2-api.f5.com/qkview-analyzer/api"

class iHealthClient:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = 0

    def _get_bearer_token(self):
        """Obtain OAuth2 Bearer Token from F5 Identity"""
        print("[iHealth] Solicitando token OAuth2 a F5 Identity...")
        creds = f"{self.client_id}:{self.client_secret}"
        encoded_creds = base64.b64encode(creds.encode()).decode()
        
        headers = {
            "Authorization": f"Basic {encoded_creds}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        
        data = {
            "grant_type": "client_credentials",
            "scope": "ihealth"
        }
        
        try:
            response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
            print(f"[iHealth] Respuesta del token de F5. Código HTTP: {response.status_code}")
            response.raise_for_status()
            
            token_data = response.json()
            self.token = token_data.get("access_token")
            self.token_expiry = time.time() + token_data.get("expires_in", 1800) - 60
            print("[iHealth] Token OAuth2 obtenido y almacenado en caché con éxito.")
        except Exception as e:
            print(f"[iHealth] ERROR al solicitar token OAuth2 a F5: {e}")
            raise

    def get_token(self):
        """Get cached or new token"""
        if not self.token or time.time() > self.token_expiry:
            print("[iHealth] Token no encontrado o expirado. Generando uno nuevo...")
            self._get_bearer_token()
        return self.token

    def upload_qkview(self, file_path):
        """Upload QKView and return the iHealth QKView ID"""
        print(f"[iHealth] Iniciando proceso de subida del QKView en: {file_path}")
        token = self.get_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.f5.ihealth.api",
            "User-Agent": "iHealthWatcherBackend/1.0"
        }
        
        import re
        filename = os.path.basename(file_path)
        # Sanitize filename: replace spaces, parentheses, or any non-alphanumeric/dot/dash/underscore character with an underscore
        # to comply with F5's extremely strict filename validation rules
        clean_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        file_size = os.path.getsize(file_path)
        
        print(f"[iHealth] Nombre sanitizado para F5: '{clean_filename}' (Tamaño: {file_size} bytes)")
        print(f"[iHealth] Enviando petición POST multipart a: {API_BASE_URL}/qkviews con el campo 'qkview'")
        
        with open(file_path, 'rb') as f:
            # CORREGIDO: Se cambia el nombre del campo de 'file' a 'qkview' según lo exigido por la API de F5
            files = {'qkview': (clean_filename, f, 'application/octet-stream')}
            
            start_time = time.time()
            response = requests.post(f"{API_BASE_URL}/qkviews", headers=headers, files=files, timeout=300)
            elapsed = time.time() - start_time
            print(f"[iHealth] Petición de subida completada en {elapsed:.2f} segundos. Código HTTP: {response.status_code}")
            
            if response.status_code >= 400:
                print(f"[iHealth] ERROR de subida detectado. Respuesta de F5: {response.text}")
                raise ValueError(f"F5 iHealth upload failed ({response.status_code}): {response.text}")
                
            response.raise_for_status()
            
            data = response.json()
            qkview_id = data.get("qkview_id")
            
            if not qkview_id and "Location" in response.headers:
                qkview_id = response.headers["Location"].split("/")[-1]
                
            if not qkview_id:
                qkview_id = data.get("id") or data.get("qkviewId")
                
            if not qkview_id:
                print(f"[iHealth] ADVERTENCIA: No se pudo encontrar el QKView ID directo en el JSON. Payload: {data}")
                raise ValueError(f"Could not determine QKView ID. Response: {data}")
                
            print(f"[iHealth] QKView subido exitosamente a F5. ID Asignado: {qkview_id}")
            return qkview_id

    def check_status(self, qkview_id):
        """Check if iHealth analysis is complete"""
        print(f"[iHealth] Consultando estado del diagnóstico en F5 para el ID: {qkview_id}...")
        token = self.get_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.f5.ihealth.api",
            "User-Agent": "iHealthWatcherBackend/1.0"
        }
        
        url = f"{API_BASE_URL}/qkviews/{qkview_id}"
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        
        status = response.json().get("status", "").lower()
        print(f"[iHealth] Estado actual en iHealth para ID {qkview_id}: '{status}'")
        return status

    def get_diagnostics(self, qkview_id):
        """Retrieve diagnostic hits (JSON) from iHealth"""
        print(f"[iHealth] Descargando reporte detallado de heurísticas desde F5 para el ID: {qkview_id}...")
        token = self.get_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.f5.ihealth.api",
            "User-Agent": "iHealthWatcherBackend/1.0"
        }
        
        url = f"{API_BASE_URL}/qkviews/{qkview_id}/diagnostics?set=hit"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        print(f"[iHealth] Reporte de diagnóstico descargado con éxito para el ID: {qkview_id}")
        return response.json()
