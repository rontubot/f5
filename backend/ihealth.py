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
        
        response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
        response.raise_for_status()
        
        token_data = response.json()
        self.token = token_data.get("access_token")
        # Set expiry (default 30 mins, 1800s, subtract 60s for safety)
        self.token_expiry = time.time() + token_data.get("expires_in", 1800) - 60

    def get_token(self):
        """Get cached or new token"""
        if not self.token or time.time() > self.token_expiry:
            self._get_bearer_token()
        return self.token

    def upload_qkview(self, file_path):
        """Upload QKView and return the iHealth QKView ID"""
        token = self.get_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.f5.ihealth.api",
            "User-Agent": "iHealthWatcherBackend/1.0"
        }
        
        filename = os.path.basename(file_path)
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f, 'application/octet-stream')}
            response = requests.post(f"{API_BASE_URL}/qkviews", headers=headers, files=files, timeout=300)
            response.raise_for_status()
            
            data = response.json()
            qkview_id = data.get("qkview_id")
            
            if not qkview_id and "Location" in response.headers:
                qkview_id = response.headers["Location"].split("/")[-1]
                
            if not qkview_id:
                qkview_id = data.get("id") or data.get("qkviewId")
                
            if not qkview_id:
                raise ValueError(f"Could not determine QKView ID. Response: {data}")
                
            return qkview_id

    def check_status(self, qkview_id):
        """Check if iHealth analysis is complete"""
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
        return status

    def get_diagnostics(self, qkview_id):
        """Retrieve diagnostic hits (JSON) from iHealth"""
        token = self.get_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.f5.ihealth.api",
            "User-Agent": "iHealthWatcherBackend/1.0"
        }
        
        url = f"{API_BASE_URL}/qkviews/{qkview_id}/diagnostics?set=hit"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        return response.json()
