import requests
import json
from typing import Dict, Any, Optional

class CybersecurityAgentAPI:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        
    def query(self, message: str) -> Optional[Dict[str, Any]]:
        try:
            response = requests.post(
                f"{self.base_url}/query",
                json={"message": message},
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API Error: {e}")
            return None
            
    def detect_threats(self, log_data: str, network_data: str, threat_type: str) -> Optional[Dict[str, Any]]:
        return self.query(f"Detect {threat_type} threats in logs: {log_data}. Network data: {network_data}")
        
    def vulnerability_scan(self, target: str, scan_type: str, depth: str) -> Optional[Dict[str, Any]]:
        return self.query(f"Perform {depth} {scan_type} vulnerability scan on {target}")
        
    def incident_response(self, incident_type: str, details: str) -> Optional[Dict[str, Any]]:
        return self.query(f"Generate incident response plan for {incident_type}: {details}")
        
    def security_audit(self, framework: str, system_info: str) -> Optional[Dict[str, Any]]:
        return self.query(f"Conduct {framework} security audit for system: {system_info}")
