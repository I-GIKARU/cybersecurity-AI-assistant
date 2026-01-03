import asyncpg
import asyncio

class PostgreSQLDatabase:
    def __init__(self):
        self.connection_string = "postgresql://cyber_agent:secure_pass_2026@localhost/cybersecurity_db"
        self.pool = None
    
    async def init_pool(self):
        if not self.pool:
            self.pool = await asyncpg.create_pool(self.connection_string, min_size=1, max_size=5)
    
    async def get_security_events(self, limit: int = 100):
        await self.init_pool()
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM security_events 
                ORDER BY timestamp DESC LIMIT $1
            """, limit)
            return [dict(row) for row in rows]

# Global instance for client
db = PostgreSQLDatabase()
