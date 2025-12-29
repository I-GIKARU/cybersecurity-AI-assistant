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
            
            # Check if this is an appointment-related query
            appointment_keywords = ["appointment", "book", "schedule", "available", "slot"]
            if any(keyword in query.lower() for keyword in appointment_keywords):
                return ExecutionResult(
                    success=True,
                    result="I can help you with appointments! Please specify:\n- Book appointment: 'book appointment for [type] with [doctor]'\n- Check availability: 'check availability for [date]'\n- List appointments: 'list my appointments'",
                    metadata={"suggestion": "use_appointment_tool"}
                )
            
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
        # Import here to avoid circular imports
        from tools.threat_detection import ThreatDetectionTool
        from tools.server_security import ServerSecurityTool
        
        self.tools = {
            "llm_response": LLMResponseTool(llm, memory),
            "database_search": DatabaseSearchTool(),
            "threat_detection": ThreatDetectionTool(),
            "server_security": ServerSecurityTool(),
        }
    
    async def execute_action(self, plan: ActionPlan) -> ExecutionResult:
        # Check if query needs security tools
        query = plan.parameters.get("input", "").lower()
        
        # Security scanning keywords
        scan_keywords = ["scan", "vulnerability scan", "port scan", "network scan", "security scan"]
        ssl_keywords = ["ssl", "certificate", "https", "tls"]
        log_keywords = ["analyze log", "check log", "log analysis", "security log", "brute force"]
        port_keywords = ["open ports", "check ports", "port check"]
        
        # Server security keywords
        process_keywords = ["monitor processes", "check processes", "suspicious processes"]
        network_keywords = ["network connections", "check connections", "monitor network"]
        malware_keywords = ["scan malware", "check malware", "malware scan"]
        integrity_keywords = ["system integrity", "check integrity", "file integrity"]
        load_keywords = ["system load", "monitor load", "check load", "system resources"]
        disk_keywords = ["disk usage", "check disk", "monitor disk"]
        
        if any(keyword in query for keyword in scan_keywords):
            plan.tool_name = "threat_detection"
            plan.parameters = self._parse_scan_params(query)
            plan.parameters["action"] = "vulnerability_scan"
        elif any(keyword in query for keyword in ssl_keywords):
            plan.tool_name = "threat_detection"
            plan.parameters = self._parse_ssl_params(query)
            plan.parameters["action"] = "check_ssl_certificate"
        elif any(keyword in query for keyword in log_keywords):
            plan.tool_name = "threat_detection"
            plan.parameters = self._parse_log_params(query)
            plan.parameters["action"] = "analyze_log_file"
        elif any(keyword in query for keyword in port_keywords):
            plan.tool_name = "threat_detection"
            plan.parameters = self._parse_port_params(query)
            plan.parameters["action"] = "check_open_ports"
        elif any(keyword in query for keyword in process_keywords):
            plan.tool_name = "server_security"
            plan.parameters = {"action": "monitor_processes"}
        elif any(keyword in query for keyword in network_keywords):
            plan.tool_name = "server_security"
            plan.parameters = {"action": "check_network_connections"}
        elif any(keyword in query for keyword in malware_keywords):
            plan.tool_name = "server_security"
            plan.parameters = self._parse_malware_params(query)
            plan.parameters["action"] = "scan_for_malware"
        elif any(keyword in query for keyword in integrity_keywords):
            plan.tool_name = "server_security"
            plan.parameters = {"action": "check_system_integrity"}
        elif any(keyword in query for keyword in load_keywords):
            plan.tool_name = "server_security"
            plan.parameters = {"action": "monitor_system_load"}
        elif any(keyword in query for keyword in disk_keywords):
            plan.tool_name = "server_security"
            plan.parameters = {"action": "check_disk_usage"}
        elif "brute force" in query:
            plan.tool_name = "server_security"
            plan.parameters = {"action": "detect_brute_force"}
        
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
            action = plan.parameters.get("action")
            if action == "monitor_processes":
                result = await tool.monitor_processes()
            elif action == "check_network_connections":
                result = await tool.check_network_connections()
            elif action == "scan_for_malware":
                directory = plan.parameters.get("directory", "/tmp")
                result = await tool.scan_for_malware(directory)
            elif action == "check_system_integrity":
                result = await tool.check_system_integrity()
            elif action == "detect_brute_force":
                result = await tool.detect_brute_force()
            elif action == "monitor_system_load":
                result = await tool.monitor_system_load()
            elif action == "check_disk_usage":
                result = await tool.check_disk_usage()
            else:
                result = {"error": f"Unknown server security action: {action}"}
            
            return ExecutionResult(
                success=True,
                result=json.dumps(result, indent=2),
                metadata={"tool": "server_security", "action": action}
            )
        
        return await tool.execute(plan.parameters)
    
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
