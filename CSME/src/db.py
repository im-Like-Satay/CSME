from pymemcache.client.base import PooledClient
from psycopg_pool import AsyncConnectionPool

memcache_pool: PooledClient | None = None
postgres_pool: AsyncConnectionPool | None = None
