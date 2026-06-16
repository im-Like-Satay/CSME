from typing import Any, AsyncGenerator

from asyncpg import Connection, Pool

postgres_pool: Pool | Any = None


async def get_postgres() -> AsyncGenerator[Connection, None]:
    async with postgres_pool.acquire() as conn:
        yield conn
