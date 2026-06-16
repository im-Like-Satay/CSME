from contextlib import asynccontextmanager
from urllib.parse import quote_plus

from aiomcache import Client
from asyncpg import Connection, create_pool
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

import db
from utility.setting import settings

with open("/run/secrets/postgres_password", "r") as f:
    POSTGRES_PASSWORD = f.read().strip()
    POSTGRES_PASSWORD = quote_plus(POSTGRES_PASSWORD)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # init memcache
    db.cache = Client(settings.MEMCACHED_HOST, settings.MEMCACHED_PORT, pool_size=5)

    # init postgres
    db.postgres_pool = await create_pool(
        f"postgres://{settings.POSTGRES_USER}:{POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}",
        min_size=5,
    )

    yield

    await db.postgres_pool.close()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.DOMAIN_HOST],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health(conn: Connection = Depends(db.get_postgres)):
    try:
        await conn.execute("SELECT 1")  # postgres health check

        # memcache health check
        result = db.cache.get(b"health_check")
        if result == b"ok":
            return {"status": True}
        else:
            raise Exception("Memcache check failed")
    except Exception as e:
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(e))


@app.get("/")
async def root():
    return {"status": True}


@app.get("/hi/{name}")
async def hi(name: str, conn: Connection = Depends(db.get_postgres)):
    await conn.execute("CREATE TABLE IF NOT EXISTS hi (name VARCHAR)")

    await conn.execute("INSERT INTO hi (name) VALUES ($1)", name)

    return await conn.fetch("SELECT * FROM hi")
