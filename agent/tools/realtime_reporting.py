import asyncio
import json
import time
from datetime import datetime
from typing import Dict, Any, List
from core.postgres_db import db
import os

class RealTimeSecurityReporting:
    def __init__(self):
        self.name = "realtime_security_reporting"

    async def log_security_event(self, event_type: str, severity: str, source: str = None, 
                                target: str = None, description: str = None, 
                                status: str = "detected", response_time: float = 0.0,
                                metadata: Dict = None) -> Dict[str, Any]:
        """Log a security event to the database"""
        try:
            await db.log_security_event(
                event_type, severity, source or "system", 
                target or "unknown", description or f"{event_type} detected",
                status, response_time, metadata
            )
            return {"status": "logged", "event_type": event_type}
        except Exception as e:
            return {"error": str(e)}
    
    async def get_realtime_dashboard(self) -> Dict[str, Any]:
        """Generate real-time security dashboard data"""
        try:
            # Get recent events from PostgreSQL
            recent_events = await db.get_security_events(limit=50)
            
            # Calculate basic metrics
            total_events = len(recent_events)
            severity_stats = {}
            event_type_stats = {}
            
            for event in recent_events:
                severity = event.get('severity', 'unknown')
                event_type = event.get('event_type', 'unknown')
                
                severity_stats[severity] = severity_stats.get(severity, 0) + 1
                event_type_stats[event_type] = event_type_stats.get(event_type, 0) + 1
            
            # Get current system status
            import psutil
            
            try:
                # Basic system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Network connections
                try:
                    connections = psutil.net_connections()
                    network_count = len([c for c in connections if c.status == 'ESTABLISHED'])
                except:
                    network_count = 0
                
                # Network I/O
                try:
                    net_io = psutil.net_io_counters()
                    bytes_sent = net_io.bytes_sent if net_io else 0
                    bytes_recv = net_io.bytes_recv if net_io else 0
                except:
                    bytes_sent = bytes_recv = 0
                
                # Load average
                try:
                    import os
                    load_avg = os.getloadavg()
                except:
                    load_avg = (0, 0, 0)
                
                # Additional system info
                try:
                    logged_users = len(psutil.users())
                except:
                    logged_users = 0
                
                # Open files count (system-wide approximation)
                try:
                    open_files = len(list(psutil.process_iter()))  # Use process count as approximation
                except:
                    open_files = 0
                
                # Root processes count
                try:
                    root_processes = 0
                    for proc in psutil.process_iter(['pid', 'username']):
                        try:
                            if proc.info['username'] == 'root':
                                root_processes += 1
                        except:
                            continue
                except:
                    root_processes = 0
                
                # Failed logins (check auth log)
                try:
                    import subprocess
                    result = subprocess.run(['grep', '-c', 'Failed password', '/var/log/auth.log'], 
                                          capture_output=True, text=True, timeout=5)
                    failed_logins = int(result.stdout.strip()) if result.returncode == 0 else 0
                except:
                    failed_logins = 0
                
                # Suspicious ports (non-standard listening ports)
                try:
                    suspicious_ports = 0
                    standard_ports = {22, 80, 443, 53, 25, 110, 143, 993, 995, 587, 465}
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.status == 'LISTEN' and conn.laddr.port not in standard_ports:
                            suspicious_ports += 1
                except:
                    suspicious_ports = 0
                
                # System uptime
                try:
                    import subprocess
                    uptime_result = subprocess.run(['uptime', '-p'], capture_output=True, text=True, timeout=5)
                    uptime = uptime_result.stdout.strip() if uptime_result.returncode == 0 else "Unknown"
                except:
                    try:
                        boot_time = psutil.boot_time()
                        uptime_seconds = time.time() - boot_time
                        days = int(uptime_seconds // 86400)
                        hours = int((uptime_seconds % 86400) // 3600)
                        minutes = int((uptime_seconds % 3600) // 60)
                        uptime = f"up {days} days, {hours} hours, {minutes} minutes"
                    except:
                        uptime = "Unknown"
                
                current_metrics = {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "disk_usage": (disk.used / disk.total) * 100,
                    "network_connections": network_count,
                    "active_processes": len(list(psutil.process_iter())),
                    "logged_users": logged_users,
                    "open_files": open_files,
                    "root_processes": root_processes,
                    "failed_logins": failed_logins,
                    "suspicious_ports": suspicious_ports,
                    "uptime": uptime,
                    "network_io": {
                        "bytes_sent": bytes_sent,
                        "bytes_recv": bytes_recv
                    },
                    "load_average": {
                        "1min": load_avg[0],
                        "5min": load_avg[1],
                        "15min": load_avg[2]
                    }
                }
                
            except Exception as e:
                current_metrics = {
                    "cpu_percent": 0,
                    "memory_percent": 0,
                    "disk_usage": 0,
                    "network_connections": 0,
                    "active_processes": 0,
                }
            
            return {
                "status": "success",
                "dashboard_data": {
                    "total_events": total_events,
                    "severity_breakdown": severity_stats,
                    "event_types": event_type_stats,
                    "system_metrics": current_metrics,
                    "recent_events": recent_events[:10],  # Last 10 events
                    "threat_level": "medium" if total_events > 5 else "low",
                    "timestamp": datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            return {"error": str(e)}

    async def generate_security_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        try:
            # Get events from PostgreSQL
            events = await db.get_security_events(limit=1000)
            
            # Filter events by time period (simplified)
            from datetime import datetime, timedelta
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            filtered_events = []
            for event in events:
                event_time = event.get('timestamp')
                if isinstance(event_time, str):
                    try:
                        event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                    except:
                        continue
                if event_time and event_time > cutoff_time:
                    filtered_events.append(event)
            
            report = {
                "report_generated": datetime.now().isoformat(),
                "time_period_hours": hours,
                "total_events": len(filtered_events),
                "events_by_severity": {},
                "events_by_type": {},
                "top_threats": [],
                "recommendations": []
            }
            
            # Analyze by severity and type
            for event in filtered_events:
                severity = event.get('severity', 'unknown')
                event_type = event.get('event_type', 'unknown')
                
                report["events_by_severity"][severity] = report["events_by_severity"].get(severity, 0) + 1
                report["events_by_type"][event_type] = report["events_by_type"].get(event_type, 0) + 1
            
            # Generate recommendations
            if report["events_by_severity"].get("critical", 0) > 0:
                report["recommendations"].append("URGENT: Address critical security events immediately")
            if report["events_by_severity"].get("high", 0) > 5:
                report["recommendations"].append("High number of high-severity events detected - review security posture")
            if report["total_events"] > 100:
                report["recommendations"].append("High event volume - consider implementing additional monitoring")
            
            return report
            
        except Exception as e:
            return {"error": str(e)}
    
    async def start_realtime_monitoring(self) -> Dict[str, Any]:
        """Start real-time security monitoring"""
        try:
            # Log monitoring start event
            await self.log_security_event(
                event_type="system_monitoring",
                severity="info",
                description="Real-time security monitoring started",
                status="active"
            )
            
            return {
                "monitoring_started": True,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": str(e)}
