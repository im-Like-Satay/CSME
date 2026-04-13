from pymemcache.client.base import PooledClient
from asyncpg import Pool, Connection
from typing import AsyncGenerator

memcache_pool: PooledClient | None = None
postgres_pool: Pool | None = None

async def get_postgres() -> AsyncGenerator[Connection, None]:
    async with postgres_pool.acquire() as conn:
        yield conn