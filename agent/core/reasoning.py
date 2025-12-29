from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from .memory import AgentMemory, MemoryEntry
from .perception import StructuredData
from .llm_provider import LLMProvider

class ActionPlan(BaseModel):
    action_type: str
    tool_name: str
    parameters: Dict[str, Any]
    priority: int = 1
    reasoning: str = ""

class ReasoningEngine:
    def __init__(self, llm: LLMProvider, memory: AgentMemory):
        self.llm = llm
        self.memory = memory
        self.planning_prompt = """
        You are a cybersecurity AI agent. Based on the input and context, plan the next action.
        
        Available actions:
        - threat_detection: Analyze security threats and vulnerabilities, port scanning, SSL checks
        - server_security: Monitor processes, network connections, system resources, malware scanning
        - advanced_threat_hunting: AI anomaly detection, threat intelligence, zero-day detection, blockchain analysis
        - real_incident_response: REAL automated incident response with actual system actions
        - realtime_reporting: Real-time dashboards, security reports, monitoring systems
        - llm_response: Provide cybersecurity guidance and recommendations
        
        For REAL incident response (actual file quarantine, IP blocking, process killing), use: real_incident_response|incident_response|reasoning
        For real-time dashboards and monitoring, use: realtime_reporting|reporting|reasoning
        For other security tools, use: tool_name|action_type|reasoning
        
        Return your plan as: TOOL_NAME|ACTION_TYPE|REASONING
        """
    
    async def plan_action(self, structured_input: StructuredData, session_id: str) -> ActionPlan:
        # Retrieve relevant context
        context = await self.memory.retrieve_context(session_id)
        knowledge = await self.memory.search_knowledge(structured_input.processed_content)
        
        # Build planning prompt
        context_str = self._format_context(context, knowledge)
        planning_input = f"""
        Input: {structured_input.processed_content}
        Intent: {structured_input.intent}
        Context: {context_str}
        
        Plan the next action:
        """
        
        messages = [
            {"role": "system", "content": self.planning_prompt},
            {"role": "user", "content": planning_input}
        ]
        
        response = await self.llm.generate(messages)
        return self._parse_plan(response.content, structured_input)
    
    def _format_context(self, context: List, knowledge: List) -> str:
        context_items = [f"- {entry.content}" for entry in context[-3:]]
        knowledge_items = [f"- {entry.content}" for entry in knowledge[:2]]
        
        return f"Recent context:\n{chr(10).join(context_items)}\n\nRelevant knowledge:\n{chr(10).join(knowledge_items)}"
    
    def _parse_plan(self, plan_text: str, input_data: StructuredData) -> ActionPlan:
        print(f"DEBUG: Parsing plan: {plan_text}")
        
        # Parse the LLM response to extract action plan
        parts = plan_text.split("|")
        if len(parts) >= 2:
            tool_name = parts[0].strip()
            action_type = parts[1].strip() if len(parts) > 1 else "security_query"
            reasoning = parts[2].strip() if len(parts) > 2 else "Security operation"
        else:
            # Default to llm_response if parsing fails
            tool_name = "llm_response"
            action_type = "security_query"
            reasoning = "Cybersecurity query processing"
        
        return ActionPlan(
            action_type=action_type,
            tool_name=tool_name,
            parameters={"input": input_data.processed_content},
            reasoning=reasoning
        )
