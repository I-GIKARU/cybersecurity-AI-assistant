import json
import smtplib
import os
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, Any, List
import sqlite3
import subprocess

class AIIncidentClassifier:
    def __init__(self):
        self.name = "ai_incident_classifier"
        self.db_path = "/tmp/security_events.db"
        self.reports_dir = "/tmp/security_reports"
        self.email_config = {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "security-bot@company.com",
            "sender_password": "app_password_here"
        }
        self._setup_directories()
    
    def _setup_directories(self):
        """Setup directories for reports"""
        os.makedirs(self.reports_dir, exist_ok=True)
    
    async def auto_classify_incident(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered automatic incident classification"""
        try:
            # Extract features for classification
            features = self._extract_incident_features(event_data)
            
            # AI classification logic
            classification = self._ai_classify(features)
            
            # Auto-generate incident details
            incident_details = {
                "incident_id": f"AUTO-{int(time.time())}",
                "timestamp": datetime.now().isoformat(),
                "auto_classified": True,
                "classification": classification,
                "confidence": classification["confidence"],
                "severity": classification["severity"],
                "category": classification["category"],
                "attack_vector": classification["attack_vector"],
                "affected_assets": classification["affected_assets"],
                "indicators_of_compromise": classification["iocs"],
                "recommended_actions": classification["actions"],
                "business_impact": classification["business_impact"],
                "compliance_implications": classification["compliance"],
                "raw_event_data": event_data
            }
            
            # Auto-log to database
            await self._log_classified_incident(incident_details)
            
            # Auto-generate and send reports
            if classification["severity"] in ["critical", "high"]:
                await self._auto_send_reports(incident_details)
            
            return incident_details
            
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_incident_features(self, event_data: Dict) -> Dict[str, Any]:
        """Extract features from raw event data for AI classification"""
        features = {
            "file_operations": [],
            "network_activity": [],
            "process_behavior": [],
            "system_changes": [],
            "time_patterns": [],
            "user_activity": []
        }
        
        # Analyze file operations
        if "quarantined_file" in str(event_data):
            features["file_operations"].append("suspicious_file_detected")
        if "file_modified" in str(event_data):
            features["file_operations"].append("unauthorized_modification")
        
        # Analyze network activity
        if "ip_blocked" in str(event_data):
            features["network_activity"].append("malicious_ip_detected")
        if "connection" in str(event_data):
            features["network_activity"].append("suspicious_connection")
        
        # Analyze process behavior
        if "process_terminated" in str(event_data):
            features["process_behavior"].append("malicious_process_killed")
        if "high_cpu" in str(event_data):
            features["process_behavior"].append("resource_abuse")
        
        # Time-based analysis
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:
            features["time_patterns"].append("off_hours_activity")
        
        return features
    
    def _ai_classify(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered incident classification"""
        
        # Initialize classification
        classification = {
            "category": "unknown",
            "severity": "medium",
            "attack_vector": "unknown",
            "confidence": 0.5,
            "affected_assets": [],
            "iocs": [],
            "actions": [],
            "business_impact": "low",
            "compliance": []
        }
        
        # File-based threats
        if features["file_operations"]:
            if "suspicious_file_detected" in features["file_operations"]:
                classification.update({
                    "category": "malware_infection",
                    "severity": "high",
                    "attack_vector": "malicious_file",
                    "confidence": 0.85,
                    "affected_assets": ["file_system", "endpoint"],
                    "iocs": ["suspicious_executable", "file_quarantined"],
                    "actions": [
                        "File successfully quarantined",
                        "Scan all connected systems",
                        "Review email attachments",
                        "Update antivirus signatures"
                    ],
                    "business_impact": "medium",
                    "compliance": ["PCI_DSS", "SOX"]
                })
        
        # Network-based threats
        if features["network_activity"]:
            if "malicious_ip_detected" in features["network_activity"]:
                classification.update({
                    "category": "network_intrusion",
                    "severity": "high",
                    "attack_vector": "network_compromise",
                    "confidence": 0.90,
                    "affected_assets": ["network_infrastructure", "firewall"],
                    "iocs": ["malicious_ip_blocked", "suspicious_traffic"],
                    "actions": [
                        "IP address blocked successfully",
                        "Monitor for lateral movement",
                        "Review firewall logs",
                        "Check for data exfiltration"
                    ],
                    "business_impact": "high",
                    "compliance": ["GDPR", "HIPAA"]
                })
        
        # Process-based threats
        if features["process_behavior"]:
            if "malicious_process_killed" in features["process_behavior"]:
                classification.update({
                    "category": "malicious_process",
                    "severity": "critical",
                    "attack_vector": "process_injection",
                    "confidence": 0.95,
                    "affected_assets": ["endpoint", "memory"],
                    "iocs": ["suspicious_process_terminated", "memory_injection"],
                    "actions": [
                        "Malicious process terminated",
                        "Full system scan required",
                        "Memory dump analysis",
                        "Check for persistence mechanisms"
                    ],
                    "business_impact": "critical",
                    "compliance": ["SOX", "PCI_DSS", "GDPR"]
                })
        
        # Time-based anomalies
        if features["time_patterns"]:
            if "off_hours_activity" in features["time_patterns"]:
                classification["severity"] = "high"
                classification["confidence"] += 0.1
                classification["iocs"].append("off_hours_activity")
                classification["actions"].append("Investigate user account activity")
        
        # Adjust confidence based on multiple indicators
        total_indicators = sum(len(v) for v in features.values() if isinstance(v, list))
        if total_indicators > 3:
            classification["confidence"] = min(0.95, classification["confidence"] + 0.1)
        
        return classification
    
    async def _log_classified_incident(self, incident_details: Dict):
        """Log classified incident to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events 
                (event_type, severity, source, target, description, status, response_time, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident_details["category"],
                incident_details["severity"],
                "ai_classifier",
                str(incident_details["affected_assets"]),
                f"Auto-classified {incident_details['category']} with {incident_details['confidence']:.0%} confidence",
                "classified",
                0.5,  # AI classification time
                json.dumps(incident_details)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Failed to log incident: {e}")
    
    async def _auto_send_reports(self, incident_details: Dict) -> Dict[str, Any]:
        """Automatically generate and send incident reports"""
        try:
            # Generate comprehensive report
            report = self._generate_incident_report(incident_details)
            
            # Save report to file
            report_filename = f"incident_report_{incident_details['incident_id']}.json"
            report_path = os.path.join(self.reports_dir, report_filename)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            # Generate HTML report
            html_report = self._generate_html_report(incident_details)
            html_filename = f"incident_report_{incident_details['incident_id']}.html"
            html_path = os.path.join(self.reports_dir, html_filename)
            
            with open(html_path, 'w') as f:
                f.write(html_report)
            
            # Send reports via multiple channels
            delivery_results = {
                "report_generated": True,
                "report_files": [report_path, html_path],
                "delivery_channels": []
            }
            
            # 1. Email delivery (simulated)
            email_result = await self._send_email_report(incident_details, html_path)
            delivery_results["delivery_channels"].append(email_result)
            
            # 2. Slack notification (simulated)
            slack_result = await self._send_slack_notification(incident_details)
            delivery_results["delivery_channels"].append(slack_result)
            
            # 3. SMS alert (simulated)
            sms_result = await self._send_sms_alert(incident_details)
            delivery_results["delivery_channels"].append(sms_result)
            
            # 4. SIEM integration (simulated)
            siem_result = await self._send_to_siem(incident_details)
            delivery_results["delivery_channels"].append(siem_result)
            
            return delivery_results
            
        except Exception as e:
            return {"error": str(e)}
    
    def _generate_incident_report(self, incident_details: Dict) -> Dict[str, Any]:
        """Generate comprehensive incident report"""
        return {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "automated_incident_response",
                "classification_confidence": incident_details["confidence"],
                "report_id": f"RPT-{incident_details['incident_id']}"
            },
            "executive_summary": {
                "incident_type": incident_details["category"],
                "severity": incident_details["severity"],
                "business_impact": incident_details["business_impact"],
                "status": "contained",
                "estimated_cost": self._estimate_incident_cost(incident_details)
            },
            "technical_details": incident_details,
            "timeline": [
                {
                    "timestamp": incident_details["timestamp"],
                    "event": "Incident detected and auto-classified",
                    "action": "AI analysis completed"
                },
                {
                    "timestamp": datetime.now().isoformat(),
                    "event": "Automated response executed",
                    "action": "Containment measures applied"
                }
            ],
            "compliance_impact": {
                "regulations_affected": incident_details["compliance"],
                "notification_required": len(incident_details["compliance"]) > 0,
                "deadline": "72 hours" if "GDPR" in incident_details["compliance"] else "30 days"
            },
            "recommendations": {
                "immediate": incident_details["recommended_actions"][:2],
                "short_term": incident_details["recommended_actions"][2:4],
                "long_term": [
                    "Review and update security policies",
                    "Conduct security awareness training",
                    "Implement additional monitoring"
                ]
            }
        }
    
    def _generate_html_report(self, incident_details: Dict) -> str:
        """Generate HTML incident report"""
        severity_color = {
            "critical": "#ff0000",
            "high": "#ff6600", 
            "medium": "#ffff00",
            "low": "#00ff00"
        }
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>🚨 Security Incident Report - {incident_details['incident_id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #1a1a1a; color: white; padding: 20px; text-align: center; }}
        .severity {{ color: {severity_color.get(incident_details['severity'], '#000')}; font-weight: bold; }}
        .section {{ background: white; margin: 10px 0; padding: 15px; border-left: 4px solid #007acc; }}
        .metric {{ display: flex; justify-content: space-between; margin: 5px 0; }}
        .actions {{ background: #e8f4f8; padding: 10px; border-radius: 5px; }}
        .footer {{ text-align: center; color: #666; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 SECURITY INCIDENT REPORT</h1>
        <h2>Incident ID: {incident_details['incident_id']}</h2>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h3>📊 Incident Summary</h3>
        <div class="metric">Category: <span>{incident_details['category']}</span></div>
        <div class="metric">Severity: <span class="severity">{incident_details['severity'].upper()}</span></div>
        <div class="metric">Confidence: <span>{incident_details['confidence']:.0%}</span></div>
        <div class="metric">Business Impact: <span>{incident_details['business_impact']}</span></div>
    </div>
    
    <div class="section">
        <h3>🎯 Attack Details</h3>
        <div class="metric">Attack Vector: <span>{incident_details['attack_vector']}</span></div>
        <div class="metric">Affected Assets: <span>{', '.join(incident_details['affected_assets'])}</span></div>
        <div class="metric">IOCs: <span>{', '.join(incident_details['iocs'])}</span></div>
    </div>
    
    <div class="section">
        <h3>⚡ Automated Response Actions</h3>
        <div class="actions">
            {'<br>'.join([f"✅ {action}" for action in incident_details['recommended_actions']])}
        </div>
    </div>
    
    <div class="section">
        <h3>📋 Compliance Impact</h3>
        <div class="metric">Regulations: <span>{', '.join(incident_details['compliance']) if incident_details['compliance'] else 'None'}</span></div>
    </div>
    
    <div class="footer">
        <p>🤖 Report generated by AI-Powered Cybersecurity Agent</p>
        <p>Automated Incident Response System v2.0</p>
    </div>
</body>
</html>
        """
    
    def _estimate_incident_cost(self, incident_details: Dict) -> str:
        """Estimate incident cost based on severity and impact"""
        cost_matrix = {
            "critical": "$50,000 - $500,000",
            "high": "$10,000 - $100,000", 
            "medium": "$1,000 - $25,000",
            "low": "$500 - $5,000"
        }
        return cost_matrix.get(incident_details["severity"], "$1,000 - $10,000")
    
    async def _send_email_report(self, incident_details: Dict, report_path: str) -> Dict[str, Any]:
        """Send incident report via email (simulated)"""
        recipients = [
            "soc@company.com",
            "security-team@company.com", 
            "ciso@company.com"
        ]
        
        if incident_details["severity"] == "critical":
            recipients.extend(["ceo@company.com", "cto@company.com"])
        
        # Simulate email sending
        email_log = f"/tmp/email_sent_{incident_details['incident_id']}.log"
        with open(email_log, 'w') as f:
            f.write(f"Email sent at {datetime.now().isoformat()}\n")
            f.write(f"Recipients: {', '.join(recipients)}\n")
            f.write(f"Subject: URGENT: {incident_details['severity'].upper()} Security Incident - {incident_details['incident_id']}\n")
            f.write(f"Attachment: {report_path}\n")
        
        return {
            "channel": "email",
            "status": "sent",
            "recipients": recipients,
            "log_file": email_log,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _send_slack_notification(self, incident_details: Dict) -> Dict[str, Any]:
        """Send Slack notification (simulated)"""
        slack_log = f"/tmp/slack_sent_{incident_details['incident_id']}.log"
        
        message = f"""
🚨 SECURITY INCIDENT ALERT 🚨
Incident ID: {incident_details['incident_id']}
Severity: {incident_details['severity'].upper()}
Category: {incident_details['category']}
Confidence: {incident_details['confidence']:.0%}
Status: Automatically contained
        """
        
        with open(slack_log, 'w') as f:
            f.write(f"Slack notification sent at {datetime.now().isoformat()}\n")
            f.write(f"Channel: #security-alerts\n")
            f.write(f"Message: {message}\n")
        
        return {
            "channel": "slack",
            "status": "sent", 
            "slack_channel": "#security-alerts",
            "log_file": slack_log,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _send_sms_alert(self, incident_details: Dict) -> Dict[str, Any]:
        """Send SMS alert (simulated)"""
        if incident_details["severity"] not in ["critical", "high"]:
            return {"channel": "sms", "status": "skipped", "reason": "severity_too_low"}
        
        sms_log = f"/tmp/sms_sent_{incident_details['incident_id']}.log"
        
        with open(sms_log, 'w') as f:
            f.write(f"SMS alert sent at {datetime.now().isoformat()}\n")
            f.write(f"Recipients: +1-555-SOC-TEAM, +1-555-CISO-PHONE\n")
            f.write(f"Message: URGENT: {incident_details['severity'].upper()} security incident {incident_details['incident_id']} detected and contained.\n")
        
        return {
            "channel": "sms",
            "status": "sent",
            "recipients": ["+1-555-SOC-TEAM", "+1-555-CISO-PHONE"],
            "log_file": sms_log,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _send_to_siem(self, incident_details: Dict) -> Dict[str, Any]:
        """Send to SIEM system (simulated)"""
        siem_log = f"/tmp/siem_sent_{incident_details['incident_id']}.log"
        
        siem_event = {
            "event_type": "security_incident",
            "severity": incident_details["severity"],
            "classification": incident_details["category"],
            "confidence": incident_details["confidence"],
            "iocs": incident_details["iocs"],
            "timestamp": datetime.now().isoformat()
        }
        
        with open(siem_log, 'w') as f:
            f.write(f"SIEM integration at {datetime.now().isoformat()}\n")
            f.write(f"SIEM Server: splunk.company.com:8089\n")
            f.write(f"Event: {json.dumps(siem_event, indent=2)}\n")
        
        return {
            "channel": "siem",
            "status": "sent",
            "siem_server": "splunk.company.com:8089",
            "log_file": siem_log,
            "timestamp": datetime.now().isoformat()
        }
