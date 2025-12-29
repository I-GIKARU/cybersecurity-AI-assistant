from typing import Dict, Any, List
import subprocess
import json
import os
import re
import psutil
from datetime import datetime, timedelta
import hashlib

class ServerSecurityTool:
    def __init__(self):
        self.name = "server_security"
    
    async def monitor_processes(self) -> Dict[str, Any]:
        """Monitor running processes for suspicious activity"""
        try:
            suspicious_processes = []
            high_cpu_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
                try:
                    proc_info = proc.info
                    
                    # Check for suspicious process names
                    suspicious_names = ['nc', 'netcat', 'ncat', 'socat', 'wget', 'curl', 'python -c', 'perl -e', 'bash -i']
                    if any(name in str(proc_info['cmdline']).lower() for name in suspicious_names):
                        suspicious_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': proc_info['cmdline'],
                            'cpu': proc_info['cpu_percent'],
                            'memory': proc_info['memory_percent']
                        })
                    
                    # Check for high CPU usage
                    if proc_info['cpu_percent'] > 80:
                        high_cpu_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cpu': proc_info['cpu_percent']
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'suspicious_processes': suspicious_processes,
                'high_cpu_processes': high_cpu_processes,
                'total_processes': len(list(psutil.process_iter())),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def check_network_connections(self) -> Dict[str, Any]:
        """Monitor network connections for suspicious activity"""
        try:
            suspicious_connections = []
            external_connections = []
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    # Check for external connections
                    if conn.raddr and not conn.raddr.ip.startswith(('127.', '192.168.', '10.', '172.')):
                        external_connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'pid': conn.pid,
                            'status': conn.status
                        })
                    
                    # Check for suspicious ports
                    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337]
                    if conn.raddr and conn.raddr.port in suspicious_ports:
                        suspicious_connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'pid': conn.pid,
                            'reason': f'Suspicious port {conn.raddr.port}'
                        })
            
            return {
                'suspicious_connections': suspicious_connections,
                'external_connections': external_connections[:10],  # Limit output
                'total_connections': len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED']),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def scan_for_malware(self, directory: str = "/tmp") -> Dict[str, Any]:
        """Scan for potential malware signatures"""
        try:
            suspicious_files = []
            
            # Malware signatures (simplified)
            malware_patterns = [
                b'\x4d\x5a\x90\x00',  # PE header
                b'eval(',
                b'exec(',
                b'system(',
                b'/bin/sh',
                b'/bin/bash',
                b'nc -l',
                b'wget http',
                b'curl http'
            ]
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # Skip files > 10MB
                            continue
                            
                        with open(file_path, 'rb') as f:
                            content = f.read(1024 * 1024)  # Read first 1MB
                            
                        for pattern in malware_patterns:
                            if pattern in content:
                                suspicious_files.append({
                                    'file': file_path,
                                    'pattern': pattern.decode('utf-8', errors='ignore'),
                                    'size': os.path.getsize(file_path),
                                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                                })
                                break
                                
                    except (PermissionError, OSError, UnicodeDecodeError):
                        continue
            
            return {
                'suspicious_files': suspicious_files,
                'scanned_directory': directory,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def check_system_integrity(self) -> Dict[str, Any]:
        """Check system files for modifications"""
        try:
            critical_files = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/hosts',
                '/etc/crontab',
                '/etc/ssh/sshd_config'
            ]
            
            file_status = []
            for file_path in critical_files:
                if os.path.exists(file_path):
                    stat = os.stat(file_path)
                    file_status.append({
                        'file': file_path,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'permissions': oct(stat.st_mode)[-3:]
                    })
            
            return {
                'critical_files': file_status,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def detect_brute_force(self, log_path: str = "/var/log/auth.log") -> Dict[str, Any]:
        """Detect brute force attacks from auth logs"""
        try:
            failed_attempts = {}
            suspicious_ips = []
            
            if not os.path.exists(log_path):
                return {'error': f'Log file not found: {log_path}'}
            
            # Look at last 1000 lines
            result = subprocess.run(['tail', '-1000', log_path], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                # Look for failed login attempts
                if 'Failed password' in line or 'authentication failure' in line:
                    # Extract IP address
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            
            # Flag IPs with more than 5 failed attempts
            for ip, count in failed_attempts.items():
                if count > 5:
                    suspicious_ips.append({'ip': ip, 'failed_attempts': count})
            
            return {
                'suspicious_ips': suspicious_ips,
                'total_failed_attempts': sum(failed_attempts.values()),
                'unique_ips': len(failed_attempts),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def check_disk_usage(self) -> Dict[str, Any]:
        """Monitor disk usage for potential DoS attacks"""
        try:
            disk_info = []
            alerts = []
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    percent_used = (usage.used / usage.total) * 100
                    
                    disk_info.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'total_gb': round(usage.total / (1024**3), 2),
                        'used_gb': round(usage.used / (1024**3), 2),
                        'free_gb': round(usage.free / (1024**3), 2),
                        'percent_used': round(percent_used, 2)
                    })
                    
                    if percent_used > 90:
                        alerts.append(f"Critical: {partition.mountpoint} is {percent_used:.1f}% full")
                    elif percent_used > 80:
                        alerts.append(f"Warning: {partition.mountpoint} is {percent_used:.1f}% full")
                        
                except PermissionError:
                    continue
            
            return {
                'disk_usage': disk_info,
                'alerts': alerts,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def monitor_system_load(self) -> Dict[str, Any]:
        """Monitor system load and resource usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Load average
            load_avg = os.getloadavg()
            
            # Network I/O
            net_io = psutil.net_io_counters()
            
            alerts = []
            if cpu_percent > 90:
                alerts.append(f"Critical: CPU usage at {cpu_percent}%")
            if memory.percent > 90:
                alerts.append(f"Critical: Memory usage at {memory.percent}%")
            if load_avg[0] > cpu_count * 2:
                alerts.append(f"Critical: Load average {load_avg[0]:.2f} exceeds {cpu_count * 2}")
            
            return {
                'cpu_percent': cpu_percent,
                'cpu_count': cpu_count,
                'memory_percent': memory.percent,
                'memory_available_gb': round(memory.available / (1024**3), 2),
                'load_average': {
                    '1min': load_avg[0],
                    '5min': load_avg[1],
                    '15min': load_avg[2]
                },
                'network_io': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                },
                'alerts': alerts,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
