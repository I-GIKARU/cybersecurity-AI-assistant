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
        - threat_detection: Analyze security threats and vulnerabilities
        - vulnerability_scan: Perform security scans and assessments
        - security_analysis: Analyze logs, network traffic, and security incidents
        - llm_response: Provide cybersecurity guidance and recommendations
        
        Return your plan as: ACTION_TYPE|TOOL_NAME|REASONING
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
        
        # Always use llm_response tool for cybersecurity queries - simplify the logic
        return ActionPlan(
            action_type="security_query",
            tool_name="llm_response",
            parameters={"input": input_data.processed_content},
            reasoning="Cybersecurity query processing"
        )
