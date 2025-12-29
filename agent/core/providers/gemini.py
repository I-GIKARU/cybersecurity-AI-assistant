import google.genai as genai
from typing import Dict, List, Any
from ..llm_provider import LLMProvider, LLMResponse

class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str, model_name: str = "gemini-2.0-flash-exp"):
        self.client = genai.Client(api_key=api_key)
        self.model_name = model_name
    
    async def generate(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        try:
            prompt = self._format_messages(messages)
            print(f"DEBUG: Sending prompt: {prompt[:100]}...")
            
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=[{"parts": [{"text": prompt}]}]
            )
            
            content = response.candidates[0].content.parts[0].text if response.candidates else ""
            print(f"DEBUG: Response: {content[:100] if content else 'No text'}")
            
            return LLMResponse(
                content=content,
                model=self.model_name,
                usage={"prompt_tokens": 0, "completion_tokens": 0}
            )
        except Exception as e:
            print(f"DEBUG: Error: {str(e)}")
            return LLMResponse(
                content=f"Error: {str(e)}",
                model=self.model_name,
                usage={"prompt_tokens": 0, "completion_tokens": 0}
            )
    
    async def stream_generate(self, messages: List[Dict[str, str]], **kwargs):
        prompt = self._format_messages(messages)
        # Placeholder for streaming - not implemented in new API yet
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=[{"parts": [{"text": prompt}]}]
        )
        content = response.candidates[0].content.parts[0].text if response.candidates else ""
        yield content
    
    def _format_messages(self, messages: List[Dict[str, str]]) -> str:
        formatted = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                formatted.append(f"System: {content}")
            elif role == "user":
                formatted.append(f"Human: {content}")
            elif role == "assistant":
                formatted.append(f"Assistant: {content}")
        return "\n\n".join(formatted)
