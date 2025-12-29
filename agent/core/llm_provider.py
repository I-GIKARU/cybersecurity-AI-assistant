from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class LLMResponse(BaseModel):
    content: str
    usage: Optional[Dict[str, int]] = None
    model: str
    finish_reason: Optional[str] = None

class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        pass
    
    @abstractmethod
    async def stream_generate(self, messages: List[Dict[str, str]], **kwargs):
        pass
