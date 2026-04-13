from asyncpg import create_pool, Connection
from pymemcache.client.base import PooledClient

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from contextlib import asynccontextmanager
from urllib.parse import quote_plus

import db
from utility.Setting import settings


with open("/run/secrets/postgres_password", "r") as f:
    POSTGRES_PASSWORD = f.read().strip()
    POSTGRES_PASSWORD = quote_plus(POSTGRES_PASSWORD)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # init memcache
    db.memcache_pool = PooledClient(
        f"{settings.MEMCACHED_HOST}:{settings.MEMCACHED_PORT}",
        max_pool_size=4
    )

    # init postgres
    db.postgres_pool = await create_pool(
        f"postgres://{settings.POSTGRES_USER}:{POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}",
        min_size=5
    )

    yield
    
    await db.postgres_pool.close()
    db.memcache_pool.close()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.DOMAIN_HOST],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": True}

@app.get("/hi/{name}")
async def hi(name:str, conn:Connection = Depends(db.get_postgres)):
    await conn.execute("CREATE TABLE IF NOT EXISTS hi (name VARCHAR)")

    await conn.execute("INSERT INTO hi (name) VALUES ($1)", name)

    return await conn.fetch("SELECT * FROM hi")