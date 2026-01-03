import asyncpg
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

class PostgreSQLDatabase:
    def __init__(self):
        self.connection_string = "postgresql://cyber_agent:secure_pass_2026@localhost/cybersecurity_db"
        self.pool = None
    
    async def init_pool(self):
        """Initialize connection pool"""
        if not self.pool:
            self.pool = await asyncpg.create_pool(self.connection_string, min_size=2, max_size=10)
    
    async def close_pool(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
    
    async def log_security_event(self, event_type: str, severity: str, source: str, 
                                target: str, description: str, status: str = "detected",
                                response_time: float = 0.0, metadata: Dict[str, Any] = None):
        """Log security event to PostgreSQL"""
        await self.init_pool()
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO security_events 
                (event_type, severity, source, target, description, status, response_time, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, event_type, severity, source, target, description, status, response_time, 
            json.dumps(metadata) if metadata else None)
    
    async def log_system_metrics(self, cpu_percent: float, memory_percent: float,
                               disk_usage: float, network_connections: int,
                               active_threats: int, blocked_ips: int):
        """Log system metrics to PostgreSQL"""
        await self.init_pool()
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO system_metrics 
                (cpu_percent, memory_percent, disk_usage, network_connections, active_threats, blocked_ips)
                VALUES ($1, $2, $3, $4, $5, $6)
            """, cpu_percent, memory_percent, disk_usage, network_connections, active_threats, blocked_ips)
    
    async def get_security_events(self, limit: int = 100, severity: str = None) -> List[Dict]:
        """Get recent security events"""
        await self.init_pool()
        async with self.pool.acquire() as conn:
            if severity:
                rows = await conn.fetch("""
                    SELECT * FROM security_events 
                    WHERE severity = $1 
                    ORDER BY timestamp DESC LIMIT $2
                """, severity, limit)
            else:
                rows = await conn.fetch("""
                    SELECT * FROM security_events 
                    ORDER BY timestamp DESC LIMIT $1
                """, limit)
            
            return [dict(row) for row in rows]
    
    async def get_threat_indicators(self, threat_type: str = None) -> List[Dict]:
        """Get threat indicators"""
        await self.init_pool()
        async with self.pool.acquire() as conn:
            if threat_type:
                rows = await conn.fetch("""
                    SELECT * FROM threat_indicators 
                    WHERE type = $1 
                    ORDER BY first_seen DESC
                """, threat_type)
            else:
                rows = await conn.fetch("""
                    SELECT * FROM threat_indicators 
                    ORDER BY first_seen DESC
                """)
            
            return [dict(row) for row in rows]
    
    async def add_threat_indicator(self, indicator: str, indicator_type: str,
                                 threat_level: str, description: str):
        """Add new threat indicator"""
        await self.init_pool()
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO threat_indicators (indicator, type, threat_level, description, first_seen)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (indicator) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    threat_level = $3,
                    description = $4
            """, indicator, indicator_type, threat_level, description, datetime.now())

# Global database instance
db = PostgreSQLDatabase()
