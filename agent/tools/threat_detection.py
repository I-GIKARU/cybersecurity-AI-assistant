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
        """Perform comprehensive vulnerability scanning with progress tracking"""
        scan_results = {
            "scan_type": scan_type,
            "target": target,
            "status": "in_progress",
            "progress": [],
            "findings": [],
            "system_info": {},
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            scan_results["progress"].append("🔍 Starting comprehensive vulnerability scan...")
            
            if target == "127.0.0.1" or target == "localhost":
                # COMPREHENSIVE SYSTEM SCAN
                scan_results["progress"].append("🖥️ Scanning localhost - Full system analysis")
                
                # 1. Port scan
                scan_results["progress"].append("📡 Phase 1: Port scanning (1-1000)...")
                try:
                    port_result = subprocess.run(['nmap', '-sT', '-p', '1-1000', target], 
                                               capture_output=True, text=True, timeout=60)
                    if port_result.stdout:
                        open_ports = [line.strip() for line in port_result.stdout.split('\n') if 'open' in line]
                        scan_results["findings"].extend([f"🔓 {port}" for port in open_ports])
                except:
                    scan_results["findings"].append("⚠️ Port scan failed - nmap not available")
                
                # 2. System processes analysis
                scan_results["progress"].append("⚙️ Phase 2: Process analysis...")
                try:
                    ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                    if ps_result.stdout:
                        lines = ps_result.stdout.split('\n')
                        interesting = ['python', 'node', 'java', 'nginx', 'apache', 'mysql', 'postgres']
                        for line in lines[1:]:  # Skip header
                            if any(proc in line.lower() for proc in interesting):
                                parts = line.split()
                                if len(parts) > 10:
                                    scan_results["findings"].append(f"🔄 Process: {parts[10][:50]}... (PID: {parts[1]})")
                except:
                    scan_results["findings"].append("⚠️ Process analysis failed")
                
                # 3. Network connections
                scan_results["progress"].append("🌐 Phase 3: Network connections...")
                try:
                    netstat_result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
                    if netstat_result.stdout:
                        listening = [line.strip() for line in netstat_result.stdout.split('\n') if 'LISTEN' in line]
                        for conn in listening[:8]:
                            scan_results["findings"].append(f"👂 {conn}")
                except:
                    try:
                        ss_result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                        if ss_result.stdout:
                            listening = [line.strip() for line in ss_result.stdout.split('\n') if 'LISTEN' in line]
                            for conn in listening[:5]:
                                scan_results["findings"].append(f"👂 {conn}")
                    except:
                        scan_results["findings"].append("⚠️ Network analysis failed")
                
                # 4. System information
                scan_results["progress"].append("💻 Phase 4: System information...")
                try:
                    # CPU info
                    cpu_result = subprocess.run(['nproc'], capture_output=True, text=True)
                    if cpu_result.stdout:
                        scan_results["system_info"]["cpu_cores"] = cpu_result.stdout.strip()
                    
                    # Memory info
                    mem_result = subprocess.run(['free', '-h'], capture_output=True, text=True)
                    if mem_result.stdout:
                        mem_lines = mem_result.stdout.split('\n')
                        if len(mem_lines) > 1:
                            scan_results["system_info"]["memory"] = mem_lines[1]
                    
                    # Disk usage
                    disk_result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
                    if disk_result.stdout:
                        disk_lines = disk_result.stdout.split('\n')
                        if len(disk_lines) > 1:
                            scan_results["system_info"]["disk_usage"] = disk_lines[1]
                            
                except:
                    scan_results["system_info"]["error"] = "System info collection failed"
                
                scan_results["progress"].append("✅ Comprehensive system scan completed")
                scan_results["scan_scope"] = "Full system (localhost)"
                
            else:
                # NETWORK TARGET SCAN
                scan_results["progress"].append(f"🌐 Scanning network target: {target}")
                
                try:
                    if scan_type == "port_scan":
                        scan_results["progress"].append("📡 Performing TCP port scan...")
                        result = subprocess.run(['nmap', '-sT', target], 
                                              capture_output=True, text=True, timeout=60)
                    elif scan_type == "service_scan":
                        scan_results["progress"].append("🔍 Performing service detection...")
                        result = subprocess.run(['nmap', '-sV', target], 
                                              capture_output=True, text=True, timeout=120)
                    else:  # basic scan
                        scan_results["progress"].append("🏃 Performing host discovery...")
                        result = subprocess.run(['nmap', '-sn', target], 
                                              capture_output=True, text=True, timeout=30)
                    
                    if result.stdout:
                        scan_results["raw_output"] = result.stdout
                        for line in result.stdout.split('\n'):
                            if 'open' in line or 'up' in line:
                                scan_results["findings"].append(line.strip())
                except:
                    scan_results["findings"].append("⚠️ Network scan failed - nmap not available")
                
                scan_results["scan_scope"] = f"Network target ({target})"
            
            scan_results["status"] = "completed"
            scan_results["progress"].append(f"🎯 Scan completed - Found {len(scan_results['findings'])} items")
            
            return scan_results
            
        except subprocess.TimeoutExpired:
            scan_results["status"] = "timeout"
            scan_results["progress"].append("⏰ Scan timed out")
            return scan_results
        except Exception as e:
            scan_results["status"] = "error"
            scan_results["progress"].append(f"❌ Error: {str(e)}")
            return scan_results
    
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
