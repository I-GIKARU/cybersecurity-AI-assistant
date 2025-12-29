from typing import Dict, Any, List, Optional
from pydantic import BaseModel
import json
import hashlib
from datetime import datetime

class MemoryEntry(BaseModel):
    id: str
    content: str
    metadata: Dict[str, Any] = {}
    timestamp: datetime

class AgentMemory:
    def __init__(self):
        self.conversation_history: List[MemoryEntry] = []
        self.knowledge_base: Dict[str, MemoryEntry] = {}
        self.session_context: Dict[str, Any] = {}
        self._initialize_security_knowledge()
    
    def _initialize_security_knowledge(self):
        # Add basic cybersecurity knowledge
        knowledge_items = [
            ("threat_types", "Common cybersecurity threats include malware, phishing, ransomware, DDoS attacks, insider threats, and advanced persistent threats (APTs).", {"category": "threats"}),
            ("vulnerability_management", "Vulnerability management involves identifying, assessing, prioritizing, and remediating security vulnerabilities in systems and applications.", {"category": "management"}),
            ("incident_response", "Incident response includes preparation, identification, containment, eradication, recovery, and lessons learned phases.", {"category": "response"}),
            ("security_controls", "Security controls include firewalls, intrusion detection systems, antivirus software, access controls, and security monitoring.", {"category": "controls"}),
            ("emergency_indicators", "Critical security indicators include unauthorized access attempts, data exfiltration, system compromises, and suspicious network activity.", {"category": "emergency"})
        ]
        
        for item_id, content, metadata in knowledge_items:
            entry = MemoryEntry(
                id=item_id,
                content=content,
                metadata=metadata,
                timestamp=datetime.now()
            )
            self.knowledge_base[item_id] = entry
    
    async def store_conversation(self, content: str, role: str, session_id: str) -> str:
        entry_id = self._generate_id(content)
        entry = MemoryEntry(
            id=entry_id,
            content=content,
            metadata={"role": role, "session_id": session_id},
            timestamp=datetime.now()
        )
        self.conversation_history.append(entry)
        return entry_id
    
    async def store_knowledge(self, content: str, category: str, metadata: Dict[str, Any] = None) -> str:
        entry_id = self._generate_id(content)
        entry = MemoryEntry(
            id=entry_id,
            content=content,
            metadata={"category": category, **(metadata or {})},
            timestamp=datetime.now()
        )
        self.knowledge_base[entry_id] = entry
        return entry_id
    
    async def retrieve_context(self, session_id: str, limit: int = 10) -> List[MemoryEntry]:
        return [
            entry for entry in self.conversation_history[-limit:]
            if entry.metadata.get("session_id") == session_id
        ]
    
    async def search_knowledge(self, query: str, category: Optional[str] = None) -> List[MemoryEntry]:
        results = []
        for entry in self.knowledge_base.values():
            if category and entry.metadata.get("category") != category:
                continue
            if query.lower() in entry.content.lower():
                results.append(entry)
        return results[:5]
    
    def _generate_id(self, content: str) -> str:
        return hashlib.md5(f"{content}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
