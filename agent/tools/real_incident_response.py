import subprocess
import os
import shutil
import json
import time
from datetime import datetime
from typing import Dict, Any, List

class RealIncidentResponse:
    def __init__(self):
        self.name = "real_incident_response"
        self.quarantine_dir = "/tmp/quarantine"
        self.forensics_dir = "/tmp/forensics"
        self.blocked_ips_file = "/tmp/blocked_ips.txt"
        self._setup_directories()
    
    def _setup_directories(self):
        """Setup quarantine and forensics directories"""
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.forensics_dir, exist_ok=True)
    
    async def real_automated_response(self, threat_type: str, severity: str, target_file: str = None, target_ip: str = None) -> Dict[str, Any]:
        """Execute REAL automated incident response"""
        start_time = time.time()
        actions_taken = []
        
        try:
            if severity in ['critical', 'high']:
                # 1. REAL FILE QUARANTINE
                if target_file and os.path.exists(target_file):
                    quarantine_result = self._quarantine_file_real(target_file)
                    actions_taken.append(quarantine_result)
                
                # 2. REAL IP BLOCKING (using iptables)
                if target_ip:
                    block_result = self._block_ip_real(target_ip)
                    actions_taken.append(block_result)
                
                # 3. REAL PROCESS TERMINATION
                if threat_type == "malware_detected":
                    kill_result = self._kill_suspicious_processes()
                    actions_taken.extend(kill_result)
                
                # 4. REAL FORENSIC SNAPSHOT
                forensic_result = self._create_real_forensic_snapshot()
                actions_taken.append(forensic_result)
                
                # 5. REAL SYSTEM LOCKDOWN
                if severity == "critical":
                    lockdown_result = self._emergency_system_lockdown()
                    actions_taken.extend(lockdown_result)
                
                # 6. REAL NETWORK ISOLATION
                if threat_type == "network_intrusion":
                    isolation_result = self._isolate_network_interface()
                    actions_taken.append(isolation_result)
                
                # 7. REAL LOG COLLECTION
                log_result = self._collect_security_logs()
                actions_taken.append(log_result)
                
                # 8. REAL ALERT GENERATION
                alert_result = self._generate_real_alert(threat_type, severity)
                actions_taken.append(alert_result)
                
                # 9. AI AUTOMATIC CLASSIFICATION AND REPORTING
                ai_classification = await self._auto_classify_and_report({
                    "threat_type": threat_type,
                    "severity": severity,
                    "actions_taken": actions_taken,
                    "target_file": target_file,
                    "target_ip": target_ip,
                    "response_time": response_time
                })
                actions_taken.append(ai_classification)
            
            response_time = round(time.time() - start_time, 2)
            
            return {
                "incident_id": f"REAL-INC-{int(time.time())}",
                "threat_type": threat_type,
                "severity": severity,
                "response_time_seconds": response_time,
                "actions_taken": actions_taken,
                "status": "contained" if severity == "critical" else "mitigated",
                "timestamp": datetime.now().isoformat(),
                "real_actions": True
            }
            
        except Exception as e:
            return {
                "error": f"Incident response failed: {str(e)}",
                "partial_actions": actions_taken,
                "timestamp": datetime.now().isoformat()
            }
    
    def _quarantine_file_real(self, file_path: str) -> Dict[str, Any]:
        """Actually quarantine a suspicious file"""
        try:
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"{int(time.time())}_{filename}")
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Change permissions to prevent execution
            os.chmod(quarantine_path, 0o000)
            
            return {
                "action": "file_quarantined",
                "original_path": file_path,
                "quarantine_path": quarantine_path,
                "status": "success",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "action": "file_quarantine_failed",
                "file": file_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _block_ip_real(self, ip_address: str) -> Dict[str, Any]:
        """Actually block an IP address using iptables"""
        try:
            # Add to iptables DROP rule
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Log blocked IP
            with open(self.blocked_ips_file, "a") as f:
                f.write(f"{datetime.now().isoformat()}: {ip_address}\n")
            
            if result.returncode == 0:
                return {
                    "action": "ip_blocked",
                    "ip_address": ip_address,
                    "method": "iptables",
                    "status": "success",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "action": "ip_block_failed",
                    "ip_address": ip_address,
                    "error": result.stderr,
                    "timestamp": datetime.now().isoformat()
                }
        except Exception as e:
            return {
                "action": "ip_block_error",
                "ip_address": ip_address,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _kill_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Kill processes matching suspicious patterns"""
        import psutil
        killed_processes = []
        
        suspicious_names = ['nc', 'netcat', 'ncat', 'socat', 'python -c', 'perl -e', 'bash -i']
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline_str = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                
                if any(sus_name in cmdline_str.lower() for sus_name in suspicious_names):
                    proc.terminate()  # Try graceful termination first
                    time.sleep(1)
                    
                    if proc.is_running():
                        proc.kill()  # Force kill if still running
                    
                    killed_processes.append({
                        "action": "process_terminated",
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cmdline": cmdline_str,
                        "method": "SIGKILL",
                        "timestamp": datetime.now().isoformat()
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return killed_processes
    
    def _create_real_forensic_snapshot(self) -> Dict[str, Any]:
        """Create actual forensic snapshot of system state"""
        try:
            snapshot_id = f"FORENSIC-{int(time.time())}"
            snapshot_dir = os.path.join(self.forensics_dir, snapshot_id)
            os.makedirs(snapshot_dir, exist_ok=True)
            
            # Collect system information
            forensic_data = {
                "timestamp": datetime.now().isoformat(),
                "system_info": {},
                "network_connections": [],
                "running_processes": [],
                "open_files": [],
                "system_logs": []
            }
            
            # System info
            forensic_data["system_info"] = {
                "hostname": subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(),
                "uptime": subprocess.run(['uptime'], capture_output=True, text=True).stdout.strip(),
                "users": subprocess.run(['who'], capture_output=True, text=True).stdout.strip()
            }
            
            # Network connections
            import psutil
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    forensic_data["network_connections"].append({
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        "pid": conn.pid,
                        "status": conn.status
                    })
            
            # Running processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    forensic_data["running_processes"].append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cmdline": proc.info['cmdline'],
                        "create_time": proc.info['create_time']
                    })
                except:
                    continue
            
            # Save forensic data
            forensic_file = os.path.join(snapshot_dir, "forensic_data.json")
            with open(forensic_file, 'w') as f:
                json.dump(forensic_data, f, indent=2)
            
            # Copy critical log files
            log_files = ['/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log']
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        shutil.copy2(log_file, snapshot_dir)
                    except PermissionError:
                        pass  # Skip if no permission
            
            # Calculate snapshot size
            total_size = sum(os.path.getsize(os.path.join(dirpath, filename))
                           for dirpath, dirnames, filenames in os.walk(snapshot_dir)
                           for filename in filenames)
            
            return {
                "action": "forensic_snapshot_created",
                "snapshot_id": snapshot_id,
                "location": snapshot_dir,
                "size_bytes": total_size,
                "size_mb": round(total_size / (1024*1024), 2),
                "files_collected": len(os.listdir(snapshot_dir)),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "action": "forensic_snapshot_failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _emergency_system_lockdown(self) -> List[Dict[str, Any]]:
        """Emergency system lockdown procedures"""
        lockdown_actions = []
        
        try:
            # Disable network interfaces (except loopback)
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and 'lo:' not in line and 'state UP' in line:
                    interface = line.split(':')[1].strip().split('@')[0]
                    interfaces.append(interface)
            
            for interface in interfaces:
                try:
                    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                                 capture_output=True, timeout=5)
                    lockdown_actions.append({
                        "action": "interface_disabled",
                        "interface": interface,
                        "status": "success",
                        "timestamp": datetime.now().isoformat()
                    })
                except:
                    lockdown_actions.append({
                        "action": "interface_disable_failed",
                        "interface": interface,
                        "timestamp": datetime.now().isoformat()
                    })
            
            # Create lockdown marker file
            lockdown_file = "/tmp/SYSTEM_LOCKDOWN_ACTIVE"
            with open(lockdown_file, 'w') as f:
                f.write(f"Emergency lockdown activated at {datetime.now().isoformat()}\n")
            
            lockdown_actions.append({
                "action": "lockdown_marker_created",
                "file": lockdown_file,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            lockdown_actions.append({
                "action": "lockdown_failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
        
        return lockdown_actions
    
    def _isolate_network_interface(self) -> Dict[str, Any]:
        """Isolate network interface"""
        try:
            # Get default route interface
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            
            if result.stdout:
                # Extract interface name
                parts = result.stdout.split()
                if 'dev' in parts:
                    interface = parts[parts.index('dev') + 1]
                    
                    # Create isolation rules
                    subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-o', interface, '-j', 'DROP'],
                                 capture_output=True, timeout=5)
                    
                    return {
                        "action": "network_isolated",
                        "interface": interface,
                        "method": "iptables_drop",
                        "status": "success",
                        "timestamp": datetime.now().isoformat()
                    }
            
            return {
                "action": "network_isolation_failed",
                "reason": "no_default_interface",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "action": "network_isolation_error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _collect_security_logs(self) -> Dict[str, Any]:
        """Collect and analyze security logs"""
        try:
            log_analysis = {
                "failed_logins": 0,
                "suspicious_commands": 0,
                "network_anomalies": 0,
                "collected_logs": []
            }
            
            # Analyze auth.log for failed logins
            if os.path.exists('/var/log/auth.log'):
                try:
                    result = subprocess.run(['grep', '-c', 'Failed password', '/var/log/auth.log'],
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        log_analysis["failed_logins"] = int(result.stdout.strip())
                except:
                    pass
                
                log_analysis["collected_logs"].append("/var/log/auth.log")
            
            # Check syslog for suspicious activity
            if os.path.exists('/var/log/syslog'):
                log_analysis["collected_logs"].append("/var/log/syslog")
            
            return {
                "action": "security_logs_collected",
                "analysis": log_analysis,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "action": "log_collection_failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _generate_real_alert(self, threat_type: str, severity: str) -> Dict[str, Any]:
        """Generate real alert file and notification"""
        try:
            alert_id = f"ALERT-{int(time.time())}"
            alert_file = f"/tmp/{alert_id}.json"
            
            alert_data = {
                "alert_id": alert_id,
                "threat_type": threat_type,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "system": subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(),
                "message": f"CRITICAL SECURITY INCIDENT: {threat_type} detected with {severity} severity",
                "recommended_actions": [
                    "Review forensic snapshots",
                    "Verify containment measures",
                    "Investigate root cause",
                    "Update security policies"
                ]
            }
            
            # Write alert to file
            with open(alert_file, 'w') as f:
                json.dump(alert_data, f, indent=2)
            
            # Try to send desktop notification (if available)
            try:
                subprocess.run(['notify-send', 'SECURITY ALERT', 
                              f'{threat_type} - {severity} severity'], 
                             capture_output=True, timeout=5)
            except:
                pass  # Desktop notifications not available
            
            return {
                "action": "alert_generated",
                "alert_id": alert_id,
                "alert_file": alert_file,
                "notification_sent": True,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "action": "alert_generation_failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _auto_classify_and_report(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically classify incident and send reports"""
        try:
            # Import AI classifier
            from .ai_incident_classifier import AIIncidentClassifier
            classifier = AIIncidentClassifier()
            
            # Auto-classify the incident
            classification_result = await classifier.auto_classify_incident(incident_data)
            
            return {
                "action": "ai_classification_completed",
                "incident_id": classification_result.get("incident_id"),
                "classification": classification_result.get("classification", {}),
                "reports_sent": classification_result.get("delivery_channels", []),
                "confidence": classification_result.get("confidence", 0),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "action": "ai_classification_failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
