from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from pydantic import BaseModel
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
        
        self.tools = {
            "llm_response": LLMResponseTool(llm, memory),
            "database_search": DatabaseSearchTool(),
            "threat_detection": ThreatDetectionTool(),
        }
    
    async def execute_action(self, plan: ActionPlan) -> ExecutionResult:
        # Check if query needs appointment tool
        query = plan.parameters.get("input", "").lower()
        
        # Calendar booking keywords (more specific)
        calendar_keywords = ["get time slots", "time slots for", "calendar", "specific time", "available times", "slots for"]
        
        # General appointment keywords
        appointment_keywords = ["book appointment", "schedule appointment", "book", "schedule", "emergency appointment", "routine appointment", "follow-up appointment", "book routine", "book emergency", "book follow-up"]
        
        # Availability check keywords  
        availability_keywords = ["check availability", "available slots", "check available", "show availability", "list appointments", "list my appointments"]
        
        if any(keyword in query for keyword in calendar_keywords):
            plan.tool_name = "calendar_booking"
            plan.parameters = self._parse_calendar_params(query)
        elif any(keyword in query for keyword in appointment_keywords):
            plan.tool_name = "calendar_booking"  # Use calendar booking for all appointments
            plan.parameters = self._parse_calendar_params(query)
            plan.parameters["action"] = "book_appointment"
        elif any(keyword in query for keyword in availability_keywords):
            plan.tool_name = "appointment_booking"  # Use simple booking for availability
            plan.parameters = self._parse_appointment_params(query)
        
        tool = self.tools.get(plan.tool_name)
        if not tool:
            return ExecutionResult(
                success=False,
                result="",
                error=f"Tool '{plan.tool_name}' not found"
            )
        
        return await tool.execute(plan.parameters)
    
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
