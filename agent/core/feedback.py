from typing import Dict, Any, Optional
from pydantic import BaseModel
from .memory import AgentMemory
from .executor import ExecutionResult
from .reasoning import ActionPlan

class FeedbackData(BaseModel):
    execution_result: ExecutionResult
    action_plan: ActionPlan
    user_satisfaction: Optional[float] = None
    corrections: Optional[str] = None

class OutputFormat(BaseModel):
    response: str
    confidence: float
    sources: list
    session_id: str
    metadata: Dict[str, Any] = {}

class FeedbackEngine:
    def __init__(self, memory: AgentMemory):
        self.memory = memory
    
    async def process_feedback(self, feedback: FeedbackData, session_id: str) -> OutputFormat:
        # Store execution results in memory
        await self.memory.store_conversation(
            content=f"Action: {feedback.action_plan.action_type} - Result: {feedback.execution_result.success}",
            role="system",
            session_id=session_id
        )
        
        # Calculate enhanced confidence
        confidence = self._calculate_confidence(feedback)
        
        # Update agent state based on feedback
        if feedback.user_satisfaction is not None:
            await self._update_performance_metrics(feedback.user_satisfaction, feedback.action_plan)
        
        # Format final output
        return self._format_output(feedback, session_id, confidence)
    
    def _calculate_confidence(self, feedback: FeedbackData) -> float:
        """Enhanced confidence calculation based on multiple factors"""
        base_confidence = 0.5
        
        # Execution success boost
        if feedback.execution_result.success:
            base_confidence += 0.3
        
        # Action type confidence
        action_confidence = {
            "medical_query": 0.15,
            "appointment_booking": 0.25,
            "emergency_assessment": 0.1,  # Lower for safety
            "routine_query": 0.2
        }
        base_confidence += action_confidence.get(feedback.action_plan.action_type, 0.1)
        
        # Knowledge source boost
        sources_count = len(feedback.execution_result.metadata.get("sources", []))
        if sources_count > 0:
            base_confidence += min(sources_count * 0.05, 0.15)
        
        # Response quality indicators
        response_text = str(feedback.execution_result.result).lower()
        
        # Medical safety keywords reduce confidence (appropriate caution)
        safety_keywords = ["emergency", "urgent", "serious", "immediately", "911"]
        if any(keyword in response_text for keyword in safety_keywords):
            base_confidence = min(base_confidence, 0.85)  # Cap at 85% for safety
        
        # Structured response boost
        if any(indicator in response_text for indicator in ["•", "-", "1.", "2.", "steps:", "recommendations:"]):
            base_confidence += 0.05
        
        # Appointment booking success
        if "appointment booked successfully" in response_text:
            base_confidence = 0.95
        
        # Available slots response
        if "available appointment slots" in response_text:
            base_confidence = 0.92
        
        # Ensure confidence is within bounds
        return min(max(base_confidence, 0.1), 1.0)
    
    async def _update_performance_metrics(self, satisfaction: float, plan: ActionPlan):
        # Store performance data for future improvements
        await self.memory.store_knowledge(
            content=f"Action {plan.action_type} received satisfaction score: {satisfaction}",
            category="performance",
            metadata={"satisfaction": satisfaction, "action_type": plan.action_type}
        )
    
    def _format_output(self, feedback: FeedbackData, session_id: str, confidence: float) -> OutputFormat:
        result = feedback.execution_result.result
        
        return OutputFormat(
            response=str(result),
            confidence=confidence,
            sources=feedback.execution_result.metadata.get("sources", []),
            session_id=session_id,
            metadata={
                "action_taken": feedback.action_plan.action_type,
                "tool_used": feedback.action_plan.tool_name,
                "success": feedback.execution_result.success,
                "confidence_factors": self._get_confidence_breakdown(feedback)
            }
        )
    
    def _get_confidence_breakdown(self, feedback: FeedbackData) -> Dict[str, Any]:
        """Provide transparency on confidence calculation"""
        return {
            "execution_success": feedback.execution_result.success,
            "action_type": feedback.action_plan.action_type,
            "has_sources": len(feedback.execution_result.metadata.get("sources", [])) > 0,
            "response_length": len(str(feedback.execution_result.result))
        }
