from typing import Dict, Any, List, Union
from pydantic import BaseModel
import json

class InputData(BaseModel):
    content: str
    input_type: str  # text, image, log, json
    metadata: Dict[str, Any] = {}

class StructuredData(BaseModel):
    processed_content: str
    entities: List[Dict[str, Any]] = []
    intent: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = {}

class PerceptionEngine:
    def __init__(self):
        self.processors = {
            "text": self._process_text,
            "image": self._process_image,
            "log": self._process_log,
            "json": self._process_json
        }
    
    async def ingest(self, raw_input: Union[str, Dict[str, Any]], input_type: str = "text") -> StructuredData:
        input_data = InputData(
            content=str(raw_input),
            input_type=input_type
        )
        
        processor = self.processors.get(input_type, self._process_text)
        return await processor(input_data)
    
    async def _process_text(self, data: InputData) -> StructuredData:
        # Basic text processing and entity extraction
        return StructuredData(
            processed_content=data.content.strip(),
            intent="security_query",
            confidence=0.8
        )
    
    async def _process_image(self, data: InputData) -> StructuredData:
        # Placeholder for image processing
        return StructuredData(
            processed_content=f"Image data: {data.content}",
            intent="image_analysis",
            confidence=0.7
        )
    
    async def _process_log(self, data: InputData) -> StructuredData:
        # Log parsing and structuring
        return StructuredData(
            processed_content=data.content,
            intent="log_analysis",
            confidence=0.9
        )
    
    async def _process_json(self, data: InputData) -> StructuredData:
        try:
            parsed = json.loads(data.content)
            return StructuredData(
                processed_content=json.dumps(parsed, indent=2),
                intent="structured_data",
                confidence=1.0,
                metadata=parsed
            )
        except json.JSONDecodeError:
            return StructuredData(
                processed_content=data.content,
                intent="malformed_json",
                confidence=0.3
            )
