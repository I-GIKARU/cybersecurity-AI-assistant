from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from pydantic import BaseModel
import json
from .reasoning import ActionPlan
from .llm_provider import LLMProvider
from .memory import AgentMemory

class ExecutionResult(BaseModel):
    success: bool
    result: Any
    error: Optional[str] = None
    metadata: Dict[str, Any] = {}

class Tool(ABC):
    @abstractmethod
    async def execute(self, parameters: Dict[str, Any]) -> ExecutionResult:
        pass

class LLMResponseTool(Tool):
    def __init__(self, llm: LLMProvider, memory: AgentMemory):
        self.llm = llm
        self.memory = memory
    
    async def execute(self, parameters: Dict[str, Any]) -> ExecutionResult:
        try:
            query = parameters.get("input", "")
            
            # Get relevant knowledge using simple search
            knowledge = await self.memory.search_knowledge(query)
            context = "\n".join([f"- {entry.content}" for entry in knowledge[:3]])
            
            system_prompt = f"""You are a cybersecurity AI assistant. Use the following relevant information to provide accurate responses:

{context}

Always provide actionable security recommendations and best practices."""
            
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": query}
            ]
            
            response = await self.llm.generate(messages)
            
            return ExecutionResult(
                success=True, 
                result=response.content,
                metadata={
                    "sources": [entry.id for entry in knowledge[:3]],
                    "knowledge_count": len(knowledge),
                    "response_type": "knowledge_enhanced"
                }
            )
        except Exception as e:
            return ExecutionResult(success=False, result="", error=str(e))

class DatabaseSearchTool(Tool):
    async def execute(self, parameters: Dict[str, Any]) -> ExecutionResult:
        query = parameters.get("query", "")
        return ExecutionResult(
            success=True,
            result=f"Database search results for: {query}",
            metadata={"records_found": 0}
        )

class ToolExecutor:
    def __init__(self, llm: LLMProvider, memory: AgentMemory):
        self.llm = llm  # Store LLM for routing decisions
        # Import here to avoid circular imports
        from tools.advanced_threat_hunting import AdvancedThreatHunting
        from tools.server_security import ServerSecurityTool
        from tools.real_incident_response import RealIncidentResponse
        from tools.realtime_reporting import RealTimeSecurityReporting
        from tools.ai_incident_classifier import AIIncidentClassifier
        
        self.tools = {
            "llm_response": LLMResponseTool(llm, memory),
            "database_search": DatabaseSearchTool(),
            "threat_detection": AdvancedThreatHunting(),  # Use advanced version
            "server_security": ServerSecurityTool(),
            "advanced_threat_hunting": AdvancedThreatHunting(),
            "real_incident_response": RealIncidentResponse(),
            "realtime_reporting": RealTimeSecurityReporting(),
            "ai_incident_classifier": AIIncidentClassifier(),
        }
    
    async def execute_action(self, plan: ActionPlan) -> ExecutionResult:
        # Use the planned tool directly instead of keyword matching
        tool_name = plan.tool_name
        query = plan.parameters.get("input", "").lower()
        
        # Use LLM to intelligently route requests instead of keyword matching
        if tool_name == "llm_response":
            # Let LLM decide how to route the request
            routing_decision = await self._llm_route_request(plan.parameters.get("input", ""))
            
            if routing_decision["tool"] != "llm_response":
                plan.tool_name = routing_decision["tool"]
                plan.parameters = routing_decision["parameters"]
        
        # For realtime_reporting, set up parameters
        if plan.tool_name == "realtime_reporting":
            if "action" not in plan.parameters:
                if "dashboard" in query:
                    plan.parameters["action"] = "get_realtime_dashboard"
                elif "report" in query:
                    plan.parameters["action"] = "generate_security_report"
                elif "monitoring" in query:
                    plan.parameters["action"] = "start_realtime_monitoring"
                else:
                    plan.parameters["action"] = "get_realtime_dashboard"
        
        # For real_incident_response, set up parameters  
        if plan.tool_name == "real_incident_response":
            if "action" not in plan.parameters:
                plan.parameters = self._parse_real_incident_params(query)
                plan.parameters["action"] = "real_automated_response"
        
        tool = self.tools.get(plan.tool_name)
        if not tool:
            return ExecutionResult(
                success=False,
                result="",
                error=f"Tool '{plan.tool_name}' not found"
            )
        
        # Execute security tool actions
        if plan.tool_name == "threat_detection":
            action = plan.parameters.get("action")
            if action == "vulnerability_scan":
                target = plan.parameters.get("target", "127.0.0.1")
                scan_type = plan.parameters.get("scan_type", "basic")
                result = await tool.vulnerability_scan(target, scan_type)
            elif action == "check_ssl_certificate":
                hostname = plan.parameters.get("hostname", "google.com")
                port = plan.parameters.get("port", 443)
                result = await tool.check_ssl_certificate(hostname, port)
            elif action == "analyze_log_file":
                log_path = plan.parameters.get("log_path", "/var/log/auth.log")
                pattern = plan.parameters.get("pattern")
                result = await tool.analyze_log_file(log_path, pattern)
            elif action == "check_open_ports":
                target = plan.parameters.get("target", "127.0.0.1")
                result = await tool.check_open_ports(target)
            else:
                result = await tool.detect_threats("", "", "")
            
            return ExecutionResult(
                success=True,
                result=json.dumps(result, indent=2),
                metadata={"tool": "threat_detection", "action": action}
            )
        
        # Execute server security tool actions
        elif plan.tool_name == "server_security":
            action = plan.parameters.get("action", "").replace(" ", "_").lower()
            if action == "monitor_processes" or "monitor" in action and "process" in action:
                result = await tool.monitor_processes()
            elif action == "check_network_connections" or "network" in action:
                result = await tool.check_network_connections()
            elif action == "scan_for_malware" or "malware" in action:
                directory = plan.parameters.get("directory", "/tmp")
                result = await tool.scan_for_malware(directory)
            elif action == "check_system_integrity" or "integrity" in action:
                result = await tool.check_system_integrity()
            elif action == "detect_brute_force" or "brute" in action:
                result = await tool.detect_brute_force()
            elif action == "monitor_system_load" or "load" in action:
                result = await tool.monitor_system_load()
            elif action == "check_disk_usage" or "disk" in action:
                result = await tool.check_disk_usage()
            else:
                # Default to process monitoring for system issues
                result = await tool.monitor_processes()
            
            return ExecutionResult(
                success=True,
                result=json.dumps(result, indent=2),
                metadata={"tool": "server_security", "action": action}
            )
        
        # Execute advanced threat hunting actions
        elif plan.tool_name == "advanced_threat_hunting":
            action = plan.parameters.get("action")
            if action == "ai_powered_anomaly_detection":
                result = await tool.ai_powered_anomaly_detection()
            elif action == "real_time_threat_intelligence":
                indicator = plan.parameters.get("indicator", "test.com")
                result = await tool.real_time_threat_intelligence(indicator)
            elif action == "automated_incident_response":
                threat_type = plan.parameters.get("threat_type", "network_intrusion")
                severity = plan.parameters.get("severity", "high")
                result = await tool.automated_incident_response(threat_type, severity)
            elif action == "deep_packet_inspection":
                interface = plan.parameters.get("interface", "lo")
                result = await tool.deep_packet_inspection(interface)
            elif action == "zero_day_detection":
                result = await tool.zero_day_detection()
            elif action == "blockchain_threat_analysis":
                address = plan.parameters.get("address")
                result = await tool.blockchain_threat_analysis(address)
            else:
                result = {"error": f"Unknown advanced threat hunting action: {action}"}
            
            return ExecutionResult(
                success=True,
                result=json.dumps(result, indent=2),
                metadata={"tool": "advanced_threat_hunting", "action": action}
            )
        
        # Execute real incident response actions
        elif plan.tool_name == "real_incident_response":
            action = plan.parameters.get("action")
            if action == "real_automated_response":
                threat_type = plan.parameters.get("threat_type", "network_intrusion")
                severity = plan.parameters.get("severity", "high")
                target_file = plan.parameters.get("target_file")
                target_ip = plan.parameters.get("target_ip")
                result = await tool.real_automated_response(threat_type, severity, target_file, target_ip)
            else:
                result = {"error": f"Unknown real incident response action: {action}"}
            
            return ExecutionResult(
                success=True,
                result=json.dumps(result, indent=2),
                metadata={"tool": "real_incident_response", "action": action}
            )
        
        # Execute real-time reporting actions
        elif plan.tool_name == "realtime_reporting":
            action = plan.parameters.get("action")
            if action == "get_realtime_dashboard":
                result = await tool.get_realtime_dashboard()
            elif action == "generate_security_report":
                hours = plan.parameters.get("hours", 24)
                result = await tool.generate_security_report(hours)
            elif action == "start_realtime_monitoring":
                result = await tool.start_realtime_monitoring()
            else:
                result = {"error": f"Unknown reporting action: {action}"}
            
            # Convert datetime objects to strings for JSON serialization
            def convert_datetime(obj):
                if hasattr(obj, 'isoformat'):
                    return obj.isoformat()
                return obj
            
            def clean_result(data):
                if isinstance(data, dict):
                    return {k: clean_result(v) for k, v in data.items()}
                elif isinstance(data, list):
                    return [clean_result(item) for item in data]
                else:
                    return convert_datetime(data)
            
            cleaned_result = clean_result(result)
            
            return ExecutionResult(
                success=True,
                result=json.dumps(cleaned_result, indent=2),
                metadata={"tool": "realtime_reporting", "action": action}
            )
        
        # Execute AI incident classification
        elif plan.tool_name == "ai_incident_classifier":
            action = plan.parameters.get("action")
            if action == "auto_classify_incident":
                event_data = plan.parameters.get("event_data", {})
                result = await tool.auto_classify_incident(event_data)
            elif action == "generate_incident_report":
                incident_id = plan.parameters.get("incident_id")
                result = await tool.generate_incident_report(incident_id)
            elif action == "send_security_alert":
                incident_data = plan.parameters.get("incident_data", {})
                result = await tool.send_security_alert(incident_data)
            else:
                result = {"error": f"Unknown AI classifier action: {action}"}
            
            return ExecutionResult(
                success=True,
                result=result.get("human_response", json.dumps(result, indent=2)),
                metadata={"tool": "ai_incident_classifier", "action": action}
            )
        
        return await tool.execute(plan.parameters)
    
    async def _llm_route_request(self, user_input: str) -> Dict[str, Any]:
        """Use LLM to intelligently route user requests to appropriate tools"""
        try:
            # Create routing prompt
            routing_prompt = f"""
You are a cybersecurity system router. Analyze the user's request and determine which tool should handle it.

USER REQUEST: "{user_input}"

AVAILABLE TOOLS:
- ai_incident_classifier: For security incidents, problems, suspicious activity, malware, attacks
- threat_detection: For technical scans (vulnerability scan, port scan, SSL check)
- server_security: For system monitoring (check processes, monitor network, system load)
- advanced_threat_hunting: For threat intelligence, anomaly detection, deep analysis
- real_incident_response: For emergency response, containment, quarantine
- realtime_reporting: For dashboards, reports, monitoring status
- llm_response: For general cybersecurity questions and guidance

ROUTING RULES:
- If user describes ANY problem, incident, suspicious activity, malware, attacks, or security concerns → ai_incident_classifier
- If user asks for technical scans or checks → threat_detection or server_security
- If user wants dashboards or reports → realtime_reporting
- If user asks general security questions → llm_response

IMPORTANT: ALL security incidents must go through ai_incident_classifier first for human-readable responses.

Respond with ONLY a JSON object:
{{
    "tool": "tool_name",
    "action": "specific_action",
    "reasoning": "why this tool was chosen"
}}
"""

            messages = [
                {"role": "system", "content": "You are a cybersecurity system router. Respond only with valid JSON."},
                {"role": "user", "content": routing_prompt}
            ]
            
            # Get LLM routing decision
            response = await self.llm.generate(messages)
            
            try:
                decision = json.loads(response.content.strip())
                
                # Set up parameters based on tool choice
                if decision["tool"] == "ai_incident_classifier":
                    parameters = {"action": "auto_classify_incident", "event_data": {"query": user_input}}
                elif decision["tool"] == "realtime_reporting":
                    parameters = {"action": "get_realtime_dashboard"}
                else:
                    parameters = {"input": user_input}
                
                return {
                    "tool": decision["tool"],
                    "parameters": parameters
                }
                
            except json.JSONDecodeError:
                # Fallback to incident classifier for safety
                return {
                    "tool": "ai_incident_classifier",
                    "parameters": {"action": "auto_classify_incident", "event_data": {"query": user_input}}
                }
                
        except Exception as e:
            # Fallback to LLM response if routing fails
            return {
                "tool": "llm_response", 
                "parameters": {"input": user_input}
            }
    
    def _parse_scan_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for vulnerability scanning"""
        import re
        
        # Extract target IP/hostname
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        hostname_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        
        target = "127.0.0.1"  # default
        ip_match = re.search(ip_pattern, query)
        hostname_match = re.search(hostname_pattern, query)
        
        if ip_match:
            target = ip_match.group()
        elif hostname_match:
            target = hostname_match.group()
        
        # Determine scan type
        scan_type = "basic"
        if "port" in query:
            scan_type = "port_scan"
        elif "service" in query:
            scan_type = "service_scan"
        
        return {"target": target, "scan_type": scan_type}
    
    def _parse_ssl_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for SSL certificate checking"""
        import re
        
        hostname_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        hostname_match = re.search(hostname_pattern, query)
        
        hostname = hostname_match.group() if hostname_match else "google.com"
        port = 443
        
        # Check for custom port
        port_pattern = r':(\d+)'
        port_match = re.search(port_pattern, query)
        if port_match:
            port = int(port_match.group(1))
        
        return {"hostname": hostname, "port": port}
    
    def _parse_log_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for log analysis"""
        log_path = "/var/log/auth.log"  # default
        
        # Common log paths
        if "apache" in query or "httpd" in query:
            log_path = "/var/log/apache2/access.log"
        elif "nginx" in query:
            log_path = "/var/log/nginx/access.log"
        elif "syslog" in query:
            log_path = "/var/log/syslog"
        elif "kern" in query:
            log_path = "/var/log/kern.log"
        
        # Extract custom path if provided
        import re
        path_pattern = r'/[a-zA-Z0-9/_.-]+'
        path_match = re.search(path_pattern, query)
        if path_match:
            log_path = path_match.group()
        
        return {"log_path": log_path}
    
    def _parse_port_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for port checking"""
        import re
        
        # Extract target IP/hostname
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        hostname_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        
        target = "127.0.0.1"  # default
        ip_match = re.search(ip_pattern, query)
        hostname_match = re.search(hostname_pattern, query)
        
        if ip_match:
            target = ip_match.group()
        elif hostname_match:
            target = hostname_match.group()
        
        return {"target": target}
    
    def _parse_malware_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for malware scanning"""
        import re
        
        # Extract directory path if provided
        path_pattern = r'/[a-zA-Z0-9/_.-]+'
        path_match = re.search(path_pattern, query)
        
        directory = path_match.group() if path_match else "/tmp"
        
        return {"directory": directory}
    
    def _parse_threat_intel_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for threat intelligence lookup"""
        import re
        
        # Extract IP addresses, domains, or other indicators
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        
        indicator = "test.com"  # default
        
        ip_match = re.search(ip_pattern, query)
        domain_match = re.search(domain_pattern, query)
        
        if ip_match:
            indicator = ip_match.group()
        elif domain_match:
            indicator = domain_match.group()
        elif "nc -l" in query:
            indicator = "nc -l 4444"
        
        return {"indicator": indicator}
    
    def _parse_incident_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for incident response"""
        threat_type = "network_intrusion"  # default
        severity = "high"  # default
        
        if "malware" in query.lower():
            threat_type = "malware_detected"
        elif "privilege" in query.lower():
            threat_type = "privilege_escalation"
        elif "intrusion" in query.lower():
            threat_type = "network_intrusion"
        
        if "critical" in query.lower():
            severity = "critical"
        elif "medium" in query.lower():
            severity = "medium"
        elif "low" in query.lower():
            severity = "low"
        
        return {"threat_type": threat_type, "severity": severity}
    
    def _parse_blockchain_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for blockchain threat analysis"""
        import re
        
        # Extract cryptocurrency addresses (simplified)
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        
        address = None
        
        btc_match = re.search(btc_pattern, query)
        eth_match = re.search(eth_pattern, query)
        
        if btc_match:
            address = btc_match.group()
        elif eth_match:
            address = eth_match.group()
        
        return {"address": address}
    
    def _parse_real_incident_params(self, query: str) -> Dict[str, Any]:
        """Parse parameters for real incident response"""
        import re
        
        threat_type = "network_intrusion"  # default
        severity = "high"  # default
        target_file = None
        target_ip = None
        
        # Extract threat type
        if "malware" in query.lower():
            threat_type = "malware_detected"
        elif "privilege" in query.lower():
            threat_type = "privilege_escalation"
        elif "intrusion" in query.lower():
            threat_type = "network_intrusion"
        
        # Extract severity
        if "critical" in query.lower():
            severity = "critical"
        elif "medium" in query.lower():
            severity = "medium"
        elif "low" in query.lower():
            severity = "low"
        
        # Extract target file path
        file_pattern = r'/[a-zA-Z0-9/_.-]+'
        file_match = re.search(file_pattern, query)
        if file_match:
            target_file = file_match.group()
        
        # Extract target IP
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_match = re.search(ip_pattern, query)
        if ip_match:
            target_ip = ip_match.group()
        
        return {
            "threat_type": threat_type,
            "severity": severity,
            "target_file": target_file,
            "target_ip": target_ip
        }
    
    def _parse_calendar_params(self, query: str) -> Dict[str, Any]:
        """Parse calendar-specific parameters"""
        params = {"action": "get_time_slots"}
        
        if "calendar" in query:
            params["action"] = "get_calendar"
        elif "time slots" in query or "available times" in query:
            params["action"] = "get_time_slots"
        elif any(word in query for word in ["book", "schedule"]):
            params["action"] = "book_appointment"
            
            # Extract appointment type
            if "follow-up" in query or "followup" in query:
                params["type"] = "follow-up"
            elif "emergency" in query:
                params["type"] = "emergency"
            elif "routine" in query:
                params["type"] = "routine"
            else:
                params["type"] = "consultation"
            
            # Set default patient name if not specified
            params["patient_name"] = "Patient"
        
        # Extract date if mentioned
        import re
        date_pattern = r'\d{4}-\d{2}-\d{2}'
        date_match = re.search(date_pattern, query)
        if date_match:
            params["date"] = date_match.group()
        else:
            # Default to next business day
            from datetime import datetime, timedelta
            tomorrow = datetime.now() + timedelta(days=1)
            while tomorrow.weekday() >= 5:  # Skip weekends
                tomorrow += timedelta(days=1)
            params["date"] = tomorrow.strftime("%Y-%m-%d")
        
        # Extract time if mentioned
        time_pattern = r'\d{1,2}:\d{2}'
        time_match = re.search(time_pattern, query)
        if time_match:
            params["time"] = time_match.group()
        else:
            # Default to 9 AM
            params["time"] = "09:00"
        
        # Extract doctor
        if "dr." in query or "doctor" in query:
            words = query.split()
            for i, word in enumerate(words):
                if word.lower() in ["dr.", "doctor"] and i + 1 < len(words):
                    params["doctor"] = f"Dr. {words[i + 1].title()}"
                    break
        else:
            params["doctor"] = "Dr. Smith"  # Default doctor
        
        return params
    
    def _parse_appointment_params(self, query: str) -> Dict[str, Any]:
        params = {"action": "book"}  # default action
        
        if any(phrase in query for phrase in ["check availability", "available", "slots", "show availability"]):
            params["action"] = "check_availability"
        elif "list" in query and ("appointment" in query or "my appointment" in query):
            params["action"] = "list"
        elif any(phrase in query for phrase in ["book", "schedule", "emergency appointment", "routine appointment", "follow-up appointment"]):
            params["action"] = "book"
            
            # Extract appointment type
            if "follow-up" in query or "followup" in query:
                params["type"] = "follow-up"
            elif "emergency" in query:
                params["type"] = "emergency"
            elif "routine" in query:
                params["type"] = "routine"
            else:
                params["type"] = "consultation"
            
            # Extract doctor preference
            if "dr." in query or "doctor" in query:
                words = query.split()
                for i, word in enumerate(words):
                    if word.lower() in ["dr.", "doctor"] and i + 1 < len(words):
                        params["doctor"] = f"Dr. {words[i + 1].title()}"
                        break
        
        return params
    
    def register_tool(self, name: str, tool: Tool):
        self.tools[name] = tool
