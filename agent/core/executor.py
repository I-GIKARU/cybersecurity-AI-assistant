from typing import Dict, Any
from .llm_provider import LLMProvider
from .memory import AgentMemory

class ToolExecutor:
    def __init__(self, llm: LLMProvider, memory: AgentMemory):
        self.llm = llm
        self.memory = memory
        self.tools = {}
        self._initialize_tools()
    
    def _initialize_tools(self):
        """Initialize all cybersecurity tools"""
        try:
            from tools.threat_detection import ThreatDetectionTool
            self.tools["threat_detection"] = ThreatDetectionTool()
        except ImportError:
            pass
            
        try:
            from tools.server_security import ServerSecurityTool
            self.tools["server_security"] = ServerSecurityTool()
        except ImportError:
            pass
            
        try:
            from tools.advanced_threat_hunting import AdvancedThreatHuntingTool
            self.tools["advanced_threat_hunting"] = AdvancedThreatHuntingTool()
        except ImportError:
            pass
            
        try:
            from tools.real_incident_response import RealIncidentResponse
            self.tools["real_incident_response"] = RealIncidentResponse()
        except ImportError:
            pass
            
        try:
            from tools.realtime_reporting import RealTimeSecurityReporting
            self.tools["realtime_reporting"] = RealTimeSecurityReporting()
        except ImportError:
            pass
            
        try:
            from tools.ai_incident_classifier import AIIncidentClassifier
            self.tools["ai_incident_classifier"] = AIIncidentClassifier()
        except ImportError:
            pass
