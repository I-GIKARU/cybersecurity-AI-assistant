from typing import Dict, Any
from .llm_provider import LLMProvider
from .providers.gemini import GeminiProvider
from .providers.openai import OpenAIProvider

class LLMFactory:
    _providers = {
        "gemini": GeminiProvider,
        "openai": OpenAIProvider,
    }
    
    @classmethod
    def create_provider(cls, provider_name: str, config: Dict[str, Any]) -> LLMProvider:
        if provider_name not in cls._providers:
            raise ValueError(f"Unknown provider: {provider_name}")
        
        provider_class = cls._providers[provider_name]
        return provider_class(**config)
    
    @classmethod
    def register_provider(cls, name: str, provider_class):
        cls._providers[name] = provider_class
