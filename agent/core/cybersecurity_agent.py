from typing import Dict, Any, Optional
import uuid
from .llm_factory import LLMFactory
from .memory import AgentMemory
from .executor import ToolExecutor
from .langgraph_workflow import CybersecurityWorkflow
from config.settings import settings

class CybersecurityAgent:
    def __init__(self):
        # Initialize LLM
        self.llm = LLMFactory.create_provider(
            settings.llm_provider,
            settings.get_llm_config()
        )
        
        # Initialize core components
        self.memory = AgentMemory()
        self.executor = ToolExecutor(self.llm, self.memory)  # Still needed for tools
        self.workflow = CybersecurityWorkflow(self.llm, self.executor.tools)
    
    async def process_query(self, message: str, session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if session_id is None:
            session_id = str(uuid.uuid4())
        
        try:
            # Use LangGraph workflow for intelligent routing
            response = await self.workflow.process_query(message)
            
            # Store interaction in memory
            await self.memory.store_conversation(message, "user", session_id)
            await self.memory.store_conversation(response, "assistant", session_id)
            
            return {
                "response": response,
                "confidence": 0.95,
                "sources": []
            }
            
        except Exception as e:
            error_response = f"Error processing query: {str(e)}"
            await self.memory.store_conversation(message, "user", session_id)
            await self.memory.store_conversation(error_response, "assistant", session_id)
            
            return {
                "response": error_response,
                "confidence": 0.1,
                "sources": []
            }
