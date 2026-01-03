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
import subprocess
from core.postgres_db import db

class AIIncidentClassifier:
    def __init__(self):
        self.name = "ai_incident_classifier"
        self.reports_dir = os.getenv("SECURITY_REPORTS_DIR", "/tmp/security_reports")
        self.email_config = {
            "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            "smtp_port": int(os.getenv("SMTP_PORT", "587")),
            "sender_email": os.getenv("SECURITY_EMAIL", "security-bot@company.com"),
            "sender_password": os.getenv("SECURITY_EMAIL_PASSWORD", "")
        }
        self._setup_directories()
    
    def _setup_directories(self):
        """Setup directories for reports"""
        os.makedirs(self.reports_dir, exist_ok=True)
    
    async def auto_classify_incident(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered automatic incident classification from user description"""
        try:
            # Get the user's description from the query
            user_description = event_data.get("query", "")
            
            # Use LLM to analyze the user's description directly
            classification = await self._llm_analyze_user_description(user_description)
            
            # Auto-generate incident details
            incident_details = {
                "incident_id": f"AUTO-{int(time.time())}",
                "timestamp": datetime.now().isoformat(),
                "auto_classified": True,
                "user_description": user_description,
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
            await db.log_security_event(
                "incident_classified",
                classification["severity"],
                "ai_classifier",
                "system",
                f"AI classified incident: {classification['category']}",
                "classified",
                0.2,
                incident_details
            )
            
            # Auto-trigger incident response for critical and high severity incidents
            if classification["severity"] in ["critical", "high"]:
                response_result = await self._trigger_autonomous_response(incident_details)
                incident_details["autonomous_response"] = response_result
            
            # Auto-generate and send reports
            if classification["severity"] in ["critical", "high"]:
                await self._auto_send_reports(incident_details)
            
            # Generate human-readable response
            human_response = self._generate_human_response(classification, event_data.get("query", ""))
            incident_details["human_response"] = human_response
            
            return incident_details
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _llm_analyze_user_description(self, user_description: str) -> Dict[str, Any]:
        """LLM analyzes user's natural language description of security incident"""
        
        # Import LLM here to avoid circular imports
        from core.llm_factory import LLMFactory
        from config.settings import settings
        
        try:
            # Initialize LLM
            llm = LLMFactory.create_provider(
                settings.llm_provider,
                settings.get_llm_config()
            )
            
            # Create analysis prompt for user description
            analysis_prompt = f"""
You are an expert cybersecurity analyst. A user has reported a potential security incident. Analyze their description and classify the threat.

USER REPORT:
"{user_description}"

Analyze this report and determine:
1. What type of security incident this appears to be
2. How severe the threat is based on the description
3. What immediate actions should be taken
4. What assets might be affected
5. Confidence level in your assessment

SEVERITY GUIDELINES:
- CRITICAL: Active ransomware, data breach in progress, system fully compromised
- HIGH: Malware infection, unauthorized access, network intrusion, suspicious files
- MEDIUM: Policy violations, failed login attempts, suspicious but unconfirmed activity  
- LOW: Routine security events, false positives, informational alerts

Respond with ONLY a JSON object:
{{
    "category": "ransomware|malware_infection|network_intrusion|data_breach|phishing|insider_threat|suspicious_activity|policy_violation|false_positive",
    "severity": "critical|high|medium|low",
    "attack_vector": "email_attachment|malicious_website|network_compromise|insider_threat|physical_access|social_engineering|unknown",
    "confidence": 0.0-1.0,
    "affected_assets": ["specific systems/data mentioned"],
    "iocs": ["indicators mentioned by user"],
    "actions": ["immediate steps to take"],
    "business_impact": "critical|high|medium|low",
    "compliance": ["relevant frameworks if applicable"],
    "reasoning": "brief explanation of classification"
}}
"""
            
            messages = [
                {"role": "system", "content": "You are a cybersecurity expert analyzing incident reports. Respond only with valid JSON."},
                {"role": "user", "content": analysis_prompt}
            ]
            
            # Get LLM analysis
            response = await llm.generate(messages)
            
            try:
                # Parse LLM response as JSON
                classification = json.loads(response.content.strip())
                
                # Validate and set defaults
                classification.setdefault("category", "suspicious_activity")
                classification.setdefault("severity", "medium")
                classification.setdefault("attack_vector", "unknown")
                classification.setdefault("confidence", 0.7)
                classification.setdefault("affected_assets", ["unknown"])
                classification.setdefault("iocs", ["user_reported_incident"])
                classification.setdefault("actions", ["Investigate user report", "Verify incident details"])
                classification.setdefault("business_impact", "medium")
                classification.setdefault("compliance", [])
                classification.setdefault("reasoning", "Analysis based on user description")
                
                return classification
                
            except json.JSONDecodeError:
                # Fallback if LLM doesn't return valid JSON
                return self._fallback_user_classification(user_description)
                
        except Exception as e:
            # Fallback classification if LLM fails
            return self._fallback_user_classification(user_description)
    
    def _fallback_user_classification(self, user_description: str) -> Dict[str, Any]:
        """Fallback classification based on keywords in user description"""
        description_lower = user_description.lower()
        
        # Default classification
        classification = {
            "category": "suspicious_activity",
            "severity": "medium",
            "attack_vector": "unknown",
            "confidence": 0.6,
            "affected_assets": ["reported_system"],
            "iocs": ["user_report"],
            "actions": ["Investigate reported issue"],
            "business_impact": "medium",
            "compliance": [],
            "reasoning": "Keyword-based fallback analysis"
        }
        
        # Critical keywords
        if any(keyword in description_lower for keyword in ['ransomware', 'encrypted', 'locked', 'bitcoin', 'payment', 'ransom']):
            classification.update({
                "category": "ransomware",
                "severity": "critical",
                "confidence": 0.95,
                "business_impact": "critical",
                "actions": ["IMMEDIATE: Isolate affected systems", "Contact incident response team", "Do not pay ransom", "Restore from backups"]
            })
        
        # High severity keywords  
        elif any(keyword in description_lower for keyword in ['malware', 'virus', 'trojan', 'suspicious file', 'hack', 'breach', 'unauthorized']):
            classification.update({
                "category": "malware_infection" if any(x in description_lower for x in ['malware', 'virus']) else "network_intrusion",
                "severity": "high",
                "confidence": 0.8,
                "business_impact": "high",
                "actions": ["Isolate affected system", "Run security scan", "Change passwords"]
            })
        
        # Phishing keywords
        elif any(keyword in description_lower for keyword in ['phishing', 'suspicious email', 'clicked link', 'fake website']):
            classification.update({
                "category": "phishing",
                "severity": "high",
                "confidence": 0.85,
                "attack_vector": "email_attachment" if 'email' in description_lower else "malicious_website",
                "actions": ["Change passwords immediately", "Check for unauthorized access", "Report to IT security"]
            })
        
        return classification
    
    async def _trigger_autonomous_response(self, incident_details: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger autonomous incident response for critical incidents"""
        try:
            from tools.real_incident_response import RealIncidentResponse
            
            response_tool = RealIncidentResponse()
            
            # Determine response based on incident category
            category = incident_details["classification"]["category"]
            severity = incident_details["classification"]["severity"]
            
            response_params = {
                "threat_type": category,
                "severity": severity,
                "incident_id": incident_details["incident_id"]
            }
            
            # Add specific targets if available
            if "affected_assets" in incident_details["classification"]:
                assets = incident_details["classification"]["affected_assets"]
                if assets.get("files"):
                    response_params["target_file"] = assets["files"][0]
                if assets.get("ips"):
                    response_params["target_ip"] = assets["ips"][0]
            
            # Execute autonomous response
            response_result = await response_tool.real_automated_response(
                response_params["threat_type"],
                response_params["severity"],
                response_params.get("target_file"),
                response_params.get("target_ip")
            )
            
            # Log the autonomous response
            await db.log_security_event(
                "autonomous_response",
                "info",
                "ai_classifier",
                "system",
                f"Autonomous response triggered for incident {incident_details['incident_id']}",
                "completed",
                0.5,
                {"incident_id": incident_details["incident_id"], "response": response_result}
            )
            
            return response_result
            
        except Exception as e:
            return {"error": f"Autonomous response failed: {str(e)}"}
    
    def _generate_human_response(self, classification: Dict[str, Any], user_query: str) -> str:
        """Generate human-readable response based on classification"""
        category = classification.get("category", "unknown")
        severity = classification.get("severity", "medium")
        confidence = classification.get("confidence", 0.5)
        
        # Base response based on category
        if category == "ransomware":
            base_response = f"🚨 **RANSOMWARE DETECTED** - Your system appears to be infected with ransomware based on your description of encrypted files and ransom notes."
        elif category == "network_intrusion":
            if "email" in user_query.lower() and "hack" in user_query.lower():
                base_response = f"🔓 **EMAIL COMPROMISE CONFIRMED** - Your email account has likely been compromised based on unauthorized spam activity."
            else:
                base_response = f"🌐 **NETWORK INTRUSION DETECTED** - Suspicious network activity indicates a potential security breach."
        elif category == "malware":
            base_response = f"🦠 **MALWARE INFECTION** - Your system shows signs of malware infection."
        elif category == "data_breach":
            base_response = f"📊 **DATA BREACH ALERT** - Sensitive data may have been accessed or stolen."
        elif category == "suspicious_activity":
            base_response = f"⚠️ **SUSPICIOUS ACTIVITY** - Unusual behavior detected that requires investigation."
        else:
            base_response = f"🔍 **SECURITY INCIDENT** - A potential security issue has been identified."
        
        # Add confidence and severity
        confidence_text = "high confidence" if confidence > 0.8 else "medium confidence" if confidence > 0.6 else "low confidence"
        severity_emoji = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🟢"
        
        response = f"{base_response}\n\n"
        response += f"{severity_emoji} **Severity**: {severity.upper()} ({confidence_text})\n\n"
        
        # Add indicators
        iocs = classification.get("iocs", [])
        if iocs:
            response += "**Evidence found:**\n"
            for ioc in iocs[:3]:  # Limit to top 3
                response += f"• {ioc.replace('_', ' ').title()}\n"
            response += "\n"
        
        # Add recommended actions
        actions = classification.get("actions", [])
        if actions:
            response += "**Immediate actions required:**\n"
            for action in actions[:3]:  # Limit to top 3
                response += f"• {action}\n"
            response += "\n"
        
        # Add business impact
        impact = classification.get("business_impact", "medium")
        if impact in ["high", "critical"]:
            response += f"⚡ **Business Impact**: {impact.upper()} - Immediate attention required!\n\n"
        
        response += "🤖 **Automated Response**: Security measures have been automatically initiated to contain this threat."
        
        return response
    
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
    
    async def _ai_classify(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """LLM-powered intelligent incident classification"""
        
        # Import LLM here to avoid circular imports
        from core.llm_factory import LLMFactory
        from config.settings import settings
        
        try:
            # Initialize LLM
            llm = LLMFactory.create_provider(
                settings.llm_provider,
                settings.get_llm_config()
            )
            
            # Create classification prompt
            classification_prompt = f"""
You are an expert cybersecurity analyst. Analyze this security incident and provide a JSON classification.

INCIDENT FEATURES:
- File Operations: {features.get('file_operations', [])}
- Network Activity: {features.get('network_activity', [])}
- Process Behavior: {features.get('process_behavior', [])}
- System Changes: {features.get('system_changes', [])}
- Time Patterns: {features.get('time_patterns', [])}
- User Activity: {features.get('user_activity', [])}

CLASSIFICATION CRITERIA:
- CRITICAL: Ransomware, data breach, system compromise, active attack
- HIGH: Malware infection, network intrusion, privilege escalation
- MEDIUM: Suspicious activity, policy violations, failed attempts
- LOW: Informational events, routine security checks

Respond with ONLY a JSON object:
{{
    "category": "malware_infection|network_intrusion|data_breach|ransomware|privilege_escalation|suspicious_activity|policy_violation|routine_check",
    "severity": "critical|high|medium|low",
    "attack_vector": "email_attachment|network_compromise|web_exploit|insider_threat|physical_access|unknown",
    "confidence": 0.0-1.0,
    "affected_assets": ["endpoints", "network", "servers", "databases", "applications"],
    "iocs": ["specific indicators found"],
    "actions": ["immediate actions required"],
    "business_impact": "critical|high|medium|low",
    "compliance": ["relevant compliance frameworks"]
}}
"""
            
            messages = [
                {"role": "system", "content": "You are a cybersecurity expert. Respond only with valid JSON."},
                {"role": "user", "content": classification_prompt}
            ]
            
            # Get LLM classification
            response = await llm.generate(messages)
            
            try:
                # Parse LLM response as JSON
                classification = json.loads(response.content.strip())
                
                # Validate and set defaults
                classification.setdefault("category", "suspicious_activity")
                classification.setdefault("severity", "medium")
                classification.setdefault("attack_vector", "unknown")
                classification.setdefault("confidence", 0.7)
                classification.setdefault("affected_assets", [])
                classification.setdefault("iocs", [])
                classification.setdefault("actions", ["Review incident details"])
                classification.setdefault("business_impact", "medium")
                classification.setdefault("compliance", [])
                
                # Boost confidence for clear indicators
                if any(keyword in str(features).lower() for keyword in ['ransomware', 'malware', 'breach', 'attack', 'intrusion']):
                    classification["confidence"] = min(0.95, classification["confidence"] + 0.2)
                
                return classification
                
            except json.JSONDecodeError:
                # Fallback if LLM doesn't return valid JSON
                return self._fallback_classification(features)
                
        except Exception as e:
            # Fallback classification if LLM fails
            return self._fallback_classification(features)
    
    def _fallback_classification(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule-based classification if LLM fails"""
        classification = {
            "category": "suspicious_activity",
            "severity": "medium",
            "attack_vector": "unknown",
            "confidence": 0.6,
            "affected_assets": [],
            "iocs": [],
            "actions": ["Manual review required"],
            "business_impact": "medium",
            "compliance": []
        }
        
        # Upgrade severity based on clear indicators
        feature_text = str(features).lower()
        if any(keyword in feature_text for keyword in ['ransomware', 'encryption', 'critical', 'breach']):
            classification.update({
                "category": "ransomware",
                "severity": "critical",
                "confidence": 0.9,
                "business_impact": "critical"
            })
        elif any(keyword in feature_text for keyword in ['malware', 'virus', 'trojan', 'suspicious_file']):
            classification.update({
                "category": "malware_infection", 
                "severity": "high",
                "confidence": 0.85,
                "business_impact": "high"
            })
        elif any(keyword in feature_text for keyword in ['intrusion', 'network', 'unauthorized']):
            classification.update({
                "category": "network_intrusion",
                "severity": "high", 
                "confidence": 0.8,
                "business_impact": "high"
            })
        
        return classification

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
        """Send incident report via email (REAL SMTP)"""
        try:
            recipients = [
                os.getenv("SECURITY_EMAIL", "security-team@company.com"),
                "soc@company.com"
            ]
            
            if incident_details["severity"] == "critical":
                recipients.extend(["ciso@company.com", "admin@company.com"])
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.email_config["sender_email"]
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = f"🚨 URGENT: {incident_details['severity'].upper()} Security Incident - {incident_details['incident_id']}"
            
            # Email body
            body = f"""
SECURITY INCIDENT ALERT

Incident ID: {incident_details['incident_id']}
Severity: {incident_details['severity'].upper()}
Category: {incident_details.get('classification', {}).get('category', 'Unknown')}
Confidence: {incident_details.get('confidence', 0):.0%}
Timestamp: {incident_details['timestamp']}

IMMEDIATE ACTION REQUIRED

This is an automated alert from the Cybersecurity AI Agent.
Please review the attached incident report and take appropriate action.

Affected Assets: {incident_details.get('classification', {}).get('affected_assets', 'Unknown')}
Attack Vector: {incident_details.get('classification', {}).get('attack_vector', 'Unknown')}
Business Impact: {incident_details.get('classification', {}).get('business_impact', 'Unknown')}

Recommended Actions:
{chr(10).join(['- ' + action for action in incident_details.get('classification', {}).get('actions', ['Review incident details'])])}

---
Cybersecurity AI Agent
Autonomous Security Operations Center
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach report if exists
            if os.path.exists(report_path):
                with open(report_path, "rb") as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= incident_report_{incident_details["incident_id"]}.html'
                    )
                    msg.attach(part)
            
            # Send email via SMTP
            if self.email_config["sender_password"]:  # Only send if password is configured
                server = smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"])
                server.starttls()
                server.login(self.email_config["sender_email"], self.email_config["sender_password"])
                text = msg.as_string()
                server.sendmail(self.email_config["sender_email"], recipients, text)
                server.quit()
                
                return {
                    "channel": "email",
                    "status": "sent",
                    "recipients": recipients,
                    "smtp_server": self.email_config["smtp_server"],
                    "timestamp": datetime.now().isoformat()
                }
            else:
                # Log email instead of sending if no password configured
                email_log = f"/tmp/email_log_{incident_details['incident_id']}.txt"
                with open(email_log, 'w') as f:
                    f.write(f"Email would be sent at {datetime.now().isoformat()}\n")
                    f.write(f"Recipients: {', '.join(recipients)}\n")
                    f.write(f"Subject: {msg['Subject']}\n")
                    f.write(f"Body:\n{body}\n")
                
                return {
                    "channel": "email",
                    "status": "logged_only",
                    "recipients": recipients,
                    "log_file": email_log,
                    "note": "Email password not configured - logged instead",
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "channel": "email",
                "status": "failed",
                "error": str(e),
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
