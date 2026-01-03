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
        - ai_incident_classifier: For ALL security incidents, problems, suspicious activity, malware, attacks, ransomware
        - threat_detection: For technical scans (vulnerability scan, port scan, SSL checks)
        - server_security: For system monitoring (check processes, monitor network, system load)
        - advanced_threat_hunting: For threat intelligence, anomaly detection, zero-day detection
        - realtime_reporting: For dashboards, reports, monitoring status
        - llm_response: For general cybersecurity questions and guidance
        
        IMPORTANT: ALL security incidents must go through ai_incident_classifier first for human-readable responses.
        
        Return your plan as: TOOL_NAME|ACTION_TYPE|REASONING
        """
    
    async def plan_action(self, structured_input: StructuredData, session_id: str) -> ActionPlan:
        # Simple pass-through - let executor handle all routing
        return ActionPlan(
            action_type="process_query",
            tool_name="llm_response",  # Default, executor will override with LLM routing
            parameters={"input": structured_input.processed_content},
            reasoning="Delegating to executor LLM routing"
        )
    
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
