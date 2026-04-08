from psycopg_pool import AsyncConnectionPool
from pymemcache.client.base import PooledClient

from fastapi import FastAPI

from contextlib import asynccontextmanager

import db
from utility.Setting import Setting

setting = Setting()


with open("/run/secrets/postgres_password", "r") as f:
    POSTGRES_PASSWORD = f.read().strip()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # init memcache
    db.memcache_pool = PooledClient(
        f"{setting.MEMCACHED_HOST}:{setting.MEMCACHED_PORT}",
        max_pool_size=4
    )

    # init postgres
    db.postgres_pool = AsyncConnectionPool(
        f"host={setting.POSTGRES_HOST} port={setting.POSTGRES_PORT} dbname={setting.POSTGRES_DB} user={setting.POSTGRES_USER} password={POSTGRES_PASSWORD}"
    )
    await db.postgres_pool.open()

    yield
    
    await db.postgres_pool.close()
    db.memcache_pool.close()

app = FastAPI(lifespan=lifespan)


@app.get("/")
async def root():
    return {"status": True}

@app.post("/user/")
async def add_user(full_name: str, username: str):
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            try:
                await cur.execute("INSERT INTO User_profile (fullname, username) VALUES (%s, %s)", (full_name, username))
                return {"msg": f"add {username} with full name {full_name}"}
            except:
                return {"msg": f"user {username} already exists"}

@app.delete("/user/fullname/{username}")
async def delete_user(username: str):
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            try:
                await cur.execute("DELETE FROM User_profile WHERE username = %s", (username,))
                return {"msg": f"delete {username}"}
            except:
                return {"msg": f"user {username} does not exists"}
            
@app.get("/user/{usernmae}")
async def get_user(username: str):
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            try:
                await cur.execute("SELECT fullname FROM User_profile WHERE username = %s", (username,))
                row = await cur.fetchone()
                return {"fullname": row[0]}
            except:
                return {"msg": f"user {username} does not exists"}