from openai import AsyncOpenAI
from typing import Dict, List, Any
from ..llm_provider import LLMProvider, LLMResponse

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model_name: str = "gpt-4"):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model_name = model_name
    
    async def generate(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        response = await self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            **kwargs
        )
        
        return LLMResponse(
            content=response.choices[0].message.content,
            model=response.model,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens
            },
            finish_reason=response.choices[0].finish_reason
        )
    
    async def stream_generate(self, messages: List[Dict[str, str]], **kwargs):
        stream = await self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            stream=True,
            **kwargs
        )
        
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
