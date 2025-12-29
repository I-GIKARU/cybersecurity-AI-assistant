from pydantic_settings import BaseSettings
from typing import Dict, Any

class Settings(BaseSettings):
    # LLM Configuration
    llm_provider: str = "gemini"
    gemini_api_key: str = ""
    # openai_api_key: str = ""
    
    # Model Configuration
    gemini_model: str = "gemini-pro"
    # openai_model: str = "gpt-4"
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    
    class Config:
        env_file = ".env"
    
    def get_llm_config(self) -> Dict[str, Any]:
        if self.llm_provider == "gemini":
            return {
                "api_key": self.gemini_api_key,
                "model_name": self.gemini_model
            }
        # elif self.llm_provider == "openai":
        #     return {
        #         "api_key": self.openai_api_key,
        #         "model_name": self.openai_model
        #     }
        else:
            raise ValueError(f"Unknown LLM provider: {self.llm_provider}")

settings = Settings()
