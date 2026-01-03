from typing import Dict, Any, Optional
import uuid
from .llm_factory import LLMFactory
from .perception import PerceptionEngine
from .memory import AgentMemory
from .reasoning import ReasoningEngine
from .executor import ToolExecutor
from .feedback import FeedbackEngine, FeedbackData
from config.settings import settings

class CybersecurityAgent:
    def __init__(self):
        # Initialize LLM
        self.llm = LLMFactory.create_provider(
            settings.llm_provider,
            settings.get_llm_config()
        )
        
        # Initialize core components
        self.perception = PerceptionEngine()
        self.memory = AgentMemory()
        self.reasoning = ReasoningEngine(self.llm, self.memory)
        self.executor = ToolExecutor(self.llm, self.memory)
        self.feedback = FeedbackEngine(self.memory)
    
    async def process_query(self, message: str, session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if session_id is None:
            session_id = str(uuid.uuid4())
        
        # Process 1.0: Perception & Data Ingestion
        structured_input = await self.perception.ingest(message, "text")
        
        # Store user input in memory
        await self.memory.store_conversation(message, "user", session_id)
        
        # Process 2.0: Agent Reasoning & Planning
        action_plan = await self.reasoning.plan_action(structured_input, session_id)
        
        # Process 3.0: Tool Execution & Action
        execution_result = await self.executor.execute_action(action_plan)
        
        # Process 4.0: Feedback & Refinement
        feedback_data = FeedbackData(
            execution_result=execution_result,
            action_plan=action_plan
        )
        
        output = await self.feedback.process_feedback(feedback_data, session_id)
        
        # Store assistant response in memory
        await self.memory.store_conversation(output.response, "assistant", session_id)
        
        return output.dict()
