import asyncio
import logging
from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from ..config.settings import settings

logger = logging.getLogger(__name__)

class Neo4jClient:
    """Async Neo4j client wrapper with context management"""
    
    def __init__(self):
        self.driver: AsyncDriver = AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
        )
        self._closed = False
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def close(self):
        if not self._closed:
            await self.driver.close()
            self._closed = True
    
    async def execute_write(self, query: str, parameters: dict = None) -> None:
        """Execute write query with automatic session management"""
        async with self.driver.session() as session:
            await session.run(query, parameters or {})
    
    async def execute_read(self, query: str, parameters: dict = None):
        """Execute read query and return results"""
        async with self.driver.session() as session:
            result = await session.run(query, parameters or {})
            return await result.data()