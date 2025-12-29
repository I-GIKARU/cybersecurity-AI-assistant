from typing import Dict, Any, Optional
import uuid
from .llm_factory import LLMFactory
from .perception import PerceptionEngine
from .memory import AgentMemory
from .reasoning import ReasoningEngine
from .executor import ToolExecutor
from .feedback import FeedbackEngine, FeedbackData
from config.settings import settings

class MedicalAgent:
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
        
        # Direct appointment routing (bypass planning for efficiency)
        query_lower = message.lower()
        
        # All appointment operations use calendar_booking for consistency
        appointment_keywords = ["get time slots", "time slots for", "book", "schedule", "book appointment", "schedule appointment", "check availability", "available slots", "list appointments", "list my appointments"]
        
        if any(keyword in query_lower for keyword in appointment_keywords):
            # Direct calendar booking for all appointment operations
            from .reasoning import ActionPlan
            
            # Determine action type
            if "list" in query_lower and "appointment" in query_lower:
                action_type = "list_appointments"
                params = {"action": "list"}
            elif "check availability" in query_lower or "available slots" in query_lower:
                action_type = "check_availability"
                params = self.executor._parse_calendar_params(query_lower)
                params["action"] = "get_time_slots"
            else:
                action_type = "book_appointment"
                params = self.executor._parse_calendar_params(query_lower)
            
            action_plan = ActionPlan(
                action_type=action_type,
                tool_name="calendar_booking",
                parameters=params,
                reasoning="Direct appointment operation"
            )
        else:
            # Process 2.0: Agent Reasoning & Planning (for non-appointment queries)
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
