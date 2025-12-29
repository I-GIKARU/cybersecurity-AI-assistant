from typing import Dict, Any
import subprocess
import json
import socket
import requests
from datetime import datetime

class ThreatDetectionTool:
    def __init__(self):
        self.name = "threat_detection"
        
    async def detect_threats(self, log_data: str, network_data: str, threat_type: str) -> Dict[str, Any]:
        return {
            "threats_found": 3,
            "threat_level": "Medium",
            "threat_types": ["Suspicious login", "Port scan", "Malware signature"],
            "recommendations": ["Block suspicious IPs", "Update firewall rules", "Run full system scan"]
        }
    
    async def vulnerability_scan(self, target: str, scan_type: str = "basic", depth: str = "normal") -> Dict[str, Any]:
        """Perform actual network vulnerability scanning using nmap"""
        try:
            if scan_type == "port_scan":
                result = subprocess.run(['nmap', '-sT', target], 
                                      capture_output=True, text=True, timeout=60)
            elif scan_type == "service_scan":
                result = subprocess.run(['nmap', '-sV', target], 
                                      capture_output=True, text=True, timeout=120)
            else:  # basic scan
                result = subprocess.run(['nmap', '-sn', target], 
                                      capture_output=True, text=True, timeout=30)
            
            return {
                "scan_type": scan_type,
                "target": target,
                "status": "completed",
                "output": result.stdout,
                "errors": result.stderr if result.stderr else None,
                "timestamp": datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {"error": "Scan timeout", "target": target}
        except FileNotFoundError:
            return {"error": "nmap not installed", "recommendation": "Install nmap: sudo apt install nmap"}
        except Exception as e:
            return {"error": str(e), "target": target}
    
    async def check_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Check SSL certificate validity and security"""
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                "hostname": hostname,
                "port": port,
                "valid": True,
                "issuer": dict(x[0] for x in cert['issuer']),
                "subject": dict(x[0] for x in cert['subject']),
                "expires": cert['notAfter'],
                "serial_number": cert['serialNumber'],
                "version": cert['version']
            }
        except Exception as e:
            return {
                "hostname": hostname,
                "port": port,
                "valid": False,
                "error": str(e)
            }
    
    async def analyze_log_file(self, log_path: str, pattern: str = None) -> Dict[str, Any]:
        """Analyze log files for security incidents"""
        try:
            suspicious_patterns = [
                r'failed login', r'authentication failure', r'invalid user',
                r'connection refused', r'permission denied', r'access denied',
                r'malware', r'virus', r'trojan', r'suspicious'
            ]
            
            if pattern:
                suspicious_patterns.append(pattern)
            
            findings = []
            with open(log_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    for pat in suspicious_patterns:
                        if pat.lower() in line.lower():
                            findings.append({
                                "line": line_num,
                                "content": line.strip(),
                                "pattern": pat,
                                "timestamp": datetime.now().isoformat()
                            })
                            break
            
            return {
                "log_file": log_path,
                "total_findings": len(findings),
                "findings": findings[:50],  # Limit to first 50
                "analysis_time": datetime.now().isoformat()
            }
        except FileNotFoundError:
            return {"error": f"Log file not found: {log_path}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def check_open_ports(self, target: str) -> Dict[str, Any]:
        """Check for open ports on target system"""
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            return {
                "target": target,
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "scan_time": datetime.now().isoformat(),
                "recommendations": self._get_port_recommendations(open_ports)
            }
        except Exception as e:
            return {"error": str(e), "target": target}
    
    def _get_port_recommendations(self, open_ports: list) -> list:
        """Get security recommendations based on open ports"""
        recommendations = []
        risky_ports = {
            21: "FTP - Consider using SFTP instead",
            23: "Telnet - Use SSH instead (port 22)",
            25: "SMTP - Ensure proper authentication",
            3389: "RDP - Restrict access and use VPN"
        }
        
        for port in open_ports:
            if port in risky_ports:
                recommendations.append(f"Port {port}: {risky_ports[port]}")
        
        return recommendations
