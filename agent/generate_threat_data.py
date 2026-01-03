import asyncio
import random
from datetime import datetime, timedelta
from core.postgres_db import db

class ThreatDataGenerator:
    def __init__(self):
        self.threat_scenarios = [
            # Critical Threats
            {
                "event_type": "ransomware_detected",
                "severity": "critical",
                "source": "threat_detection",
                "target": "workstation_042",
                "description": "Ransomware encryption detected - WannaCry variant targeting .docx files",
                "status": "active",
                "response_time": 2.1,
                "metadata": {"attack_vector": "email_attachment", "files_encrypted": 1247, "ransom_amount": "0.5 BTC"}
            },
            {
                "event_type": "data_exfiltration",
                "severity": "critical", 
                "source": "network_monitor",
                "target": "database_server",
                "description": "Large data transfer detected to suspicious IP 185.220.101.42",
                "status": "contained",
                "response_time": 1.8,
                "metadata": {"data_size": "2.3GB", "destination": "185.220.101.42", "protocol": "HTTPS"}
            },
            
            # High Severity
            {
                "event_type": "apt_activity",
                "severity": "high",
                "source": "advanced_threat_hunting",
                "target": "domain_controller",
                "description": "Advanced Persistent Threat indicators - Lazarus Group TTPs detected",
                "status": "investigating",
                "response_time": 3.2,
                "metadata": {"threat_actor": "Lazarus Group", "techniques": ["T1055", "T1083", "T1027"], "confidence": 0.87}
            },
            {
                "event_type": "privilege_escalation",
                "severity": "high",
                "source": "endpoint_detection",
                "target": "web_server_01",
                "description": "Unauthorized privilege escalation attempt using CVE-2023-4911",
                "status": "blocked",
                "response_time": 0.9,
                "metadata": {"cve": "CVE-2023-4911", "user": "www-data", "target_privilege": "root"}
            },
            {
                "event_type": "phishing_campaign",
                "severity": "high",
                "source": "email_security",
                "target": "corporate_email",
                "description": "Targeted spear-phishing campaign detected - 47 emails blocked",
                "status": "mitigated",
                "response_time": 1.5,
                "metadata": {"emails_blocked": 47, "sender_domain": "microsooft-update.com", "targets": "finance_team"}
            },
            
            # Medium Severity
            {
                "event_type": "malware_detected",
                "severity": "medium",
                "source": "antivirus",
                "target": "workstation_128",
                "description": "Trojan.GenKryptik detected in downloaded file",
                "status": "quarantined",
                "response_time": 0.5,
                "metadata": {"malware_family": "GenKryptik", "file_path": "/tmp/invoice.pdf.exe", "quarantine_id": "Q2024-001"}
            },
            {
                "event_type": "brute_force_attack",
                "severity": "medium",
                "source": "auth_monitor",
                "target": "ssh_server",
                "description": "SSH brute force attack from 203.0.113.45 - 342 failed attempts",
                "status": "blocked",
                "response_time": 0.3,
                "metadata": {"source_ip": "203.0.113.45", "failed_attempts": 342, "duration": "45 minutes"}
            },
            {
                "event_type": "suspicious_network_traffic",
                "severity": "medium",
                "source": "network_ids",
                "target": "internal_network",
                "description": "Unusual DNS queries to suspicious domains detected",
                "status": "monitoring",
                "response_time": 1.2,
                "metadata": {"suspicious_domains": ["evil-c2.tk", "malware-host.ru"], "query_count": 156}
            },
            
            # Low/Info Severity
            {
                "event_type": "policy_violation",
                "severity": "low",
                "source": "dlp_system",
                "target": "workstation_089",
                "description": "Data Loss Prevention policy violation - sensitive data in email",
                "status": "warned",
                "response_time": 0.1,
                "metadata": {"policy": "PII_EMAIL_BLOCK", "data_type": "credit_card", "action": "block_send"}
            },
            {
                "event_type": "vulnerability_scan",
                "severity": "info",
                "source": "vulnerability_scanner",
                "target": "web_application",
                "description": "Scheduled vulnerability scan completed - 3 medium findings",
                "status": "completed",
                "response_time": 0.0,
                "metadata": {"scan_type": "web_app", "findings": {"high": 0, "medium": 3, "low": 12}}
            }
        ]
    
    async def generate_realistic_threats(self, count=20):
        """Generate realistic threat scenarios"""
        print(f"Generating {count} realistic threat scenarios...")
        
        for i in range(count):
            # Select random scenario
            scenario = random.choice(self.threat_scenarios)
            
            # Add some time variation (last 7 days)
            time_offset = random.randint(0, 7 * 24 * 60)  # Random minutes in last 7 days
            timestamp = datetime.now() - timedelta(minutes=time_offset)
            
            # Add some variation to the scenario
            varied_scenario = scenario.copy()
            
            # Vary some details
            if "workstation" in scenario["target"]:
                varied_scenario["target"] = f"workstation_{random.randint(1, 200):03d}"
            
            if "IP" in scenario["description"]:
                # Generate random suspicious IP
                ip = f"{random.randint(180, 220)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                varied_scenario["description"] = scenario["description"].replace("185.220.101.42", ip)
            
            # Log to database
            await db.log_security_event(
                event_type=varied_scenario["event_type"],
                severity=varied_scenario["severity"],
                source=varied_scenario["source"],
                target=varied_scenario["target"],
                description=varied_scenario["description"],
                status=varied_scenario["status"],
                response_time=varied_scenario["response_time"],
                metadata=varied_scenario["metadata"]
            )
            
            print(f"Created: {varied_scenario['severity'].upper()} - {varied_scenario['description'][:60]}...")
        
        print(f"✅ Generated {count} realistic threat scenarios!")

async def main():
    generator = ThreatDataGenerator()
    await generator.generate_realistic_threats(25)

if __name__ == "__main__":
    asyncio.run(main())
