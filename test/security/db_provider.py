"""
db_provider.py
All database and cache access for the security module.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import uuid_utils as uuid
from fastapi import HTTPException, status

import db
from utility.Setting import settings


# ─────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────

@dataclass
class UserRecord:
    id: str
    email: str
    name: Optional[str]
    tier_slug: str
    created_at: datetime


@dataclass
class RefreshTokenRecord:
    id: str
    user_id: str
    token_hash: str
    parent_id: Optional[str]
    is_revoked: bool
    expires_at: datetime


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _rt_cache_key(token_hash: str) -> str:
    """Memcache key for a refresh token."""
    return f"rt:{token_hash}"


def _rl_cache_key(ip: str, endpoint: str) -> str:
    """Memcache key for rate limiting."""
    return f"rl:{ip}:{endpoint}"


# ─────────────────────────────────────────────
# Rate limiting  (memcache counter, app-level)
# ─────────────────────────────────────────────

def enforce_rate_limit(ip: str, endpoint: str, limit: int, window: int) -> None:
    """
    Increment a per-(ip, endpoint) counter in memcache.
    Raises HTTP 429 if the limit is exceeded within the window.

    Note: `request.client.host` will be your reverse-proxy IP when running
    behind nginx. Forward the real IP via `X-Forwarded-For` and read it in
    your middleware, then pass it here.
    """
    key = _rl_cache_key(ip, endpoint)
    mc = db.memcache_pool

    # add() only succeeds when the key does not exist → atomic initialisation
    if not mc.add(key, b"1", expire=window):
        count = mc.incr(key, 1)
        if count is None:
            # Key vanished between add() and incr() – treat as first request
            mc.add(key, b"1", expire=window)
            return
        if int(count) > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )


# ─────────────────────────────────────────────
# User CRUD
# ─────────────────────────────────────────────

async def get_user_by_email(email: str) -> Optional[UserRecord]:
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT id, email, name, tier_slug, created_at
                FROM users
                WHERE email = %s AND deleted_at IS NULL
                """,
                (email,),
            )
            row = await cur.fetchone()
    if not row:
        return None
    return UserRecord(id=str(row[0]), email=row[1], name=row[2], tier_slug=row[3], created_at=row[4])


async def get_user_by_id(user_id: str) -> Optional[UserRecord]:
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT id, email, name, tier_slug, created_at
                FROM users
                WHERE id = %s AND deleted_at IS NULL
                """,
                (user_id,),
            )
            row = await cur.fetchone()
    if not row:
        return None
    return UserRecord(id=str(row[0]), email=row[1], name=row[2], tier_slug=row[3], created_at=row[4])


async def create_user_with_credential(
    email: str, password_hash: str, name: Optional[str] = None
) -> UserRecord:
    """Create user and credential atomically."""
    user_id = str(uuid.uuid7())
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            async with conn.transaction():
                await cur.execute(
                    """
                    INSERT INTO users (id, email, name)
                    VALUES (%s, %s, %s)
                    RETURNING id, email, name, tier_slug, created_at
                    """,
                    (user_id, email, name),
                )
                row = await cur.fetchone()
                await cur.execute(
                    "INSERT INTO user_credentials (user_id, password_hash) VALUES (%s, %s)",
                    (user_id, password_hash),
                )
    return UserRecord(id=str(row[0]), email=row[1], name=row[2], tier_slug=row[3], created_at=row[4])


async def get_password_hash(user_id: str) -> Optional[str]:
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT password_hash FROM user_credentials WHERE user_id = %s",
                (user_id,),
            )
            row = await cur.fetchone()
    return row[0] if row else None


# ─────────────────────────────────────────────
# OAuth
# ─────────────────────────────────────────────

async def get_oauth_user(provider: str, provider_user_id: str) -> Optional[UserRecord]:
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT u.id, u.email, u.name, u.tier_slug, u.created_at
                FROM users u
                JOIN user_oauth o ON u.id = o.user_id
                WHERE o.provider = %s
                  AND o.provider_user_id = %s
                  AND u.deleted_at IS NULL
                """,
                (provider, provider_user_id),
            )
            row = await cur.fetchone()
    if not row:
        return None
    return UserRecord(id=str(row[0]), email=row[1], name=row[2], tier_slug=row[3], created_at=row[4])


async def create_user_with_oauth(
    email: str, provider: str, provider_user_id: str, name: Optional[str] = None
) -> UserRecord:
    """Create user and OAuth link atomically."""
    user_id = str(uuid.uuid7())
    oauth_id = str(uuid.uuid7())
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            async with conn.transaction():
                await cur.execute(
                    """
                    INSERT INTO users (id, email, name)
                    VALUES (%s, %s, %s)
                    RETURNING id, email, name, tier_slug, created_at
                    """,
                    (user_id, email, name),
                )
                row = await cur.fetchone()
                await cur.execute(
                    """
                    INSERT INTO user_oauth (id, user_id, provider, provider_user_id)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (oauth_id, user_id, provider, provider_user_id),
                )
    return UserRecord(id=str(row[0]), email=row[1], name=row[2], tier_slug=row[3], created_at=row[4])


async def link_oauth_to_existing_user(
    user_id: str, provider: str, provider_user_id: str
) -> None:
    oauth_id = str(uuid.uuid7())
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO user_oauth (id, user_id, provider, provider_user_id)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (provider, provider_user_id) DO NOTHING
                """,
                (oauth_id, user_id, provider, provider_user_id),
            )


# ─────────────────────────────────────────────
# Refresh tokens
# ─────────────────────────────────────────────

async def store_refresh_token(
    user_id: str,
    token: str,
    expires_at: datetime,
    parent_id: Optional[str] = None,
) -> str:
    """
    Hash and persist a refresh token.
    Also caches token_hash → 'user_id:token_id' in memcache with a short TTL.
    Returns the new token_id (UUID).
    """
    token_hash = _hash_token(token)
    token_id = str(uuid.uuid7())

    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO refresh_tokens (id, user_id, token_hash, parent_id, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (token_id, user_id, token_hash, parent_id, expires_at),
            )

    # Cache for fast lookup during short TTL window
    cache_val = f"{user_id}:{token_id}".encode()
    db.memcache_pool.set(
        _rt_cache_key(token_hash),
        cache_val,
        expire=settings.JWT_REFRESH_TOKEN_SHORT_EXP,
    )
    return token_id


async def get_refresh_token(token: str) -> Optional[RefreshTokenRecord]:
    """
    Look up a refresh token.  Memcache is checked first as a fast existence
    hint, but we always read from DB to get the authoritative revocation state.
    """
    token_hash = _hash_token(token)

    # Fast existence hint from memcache (avoids a DB round-trip for tokens that
    # definitely don't exist or have already been deleted from cache on revocation).
    cached = db.memcache_pool.get(_rt_cache_key(token_hash))
    if cached is None:
        # Not in cache – still check DB (token might be older than short TTL)
        pass

    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT id, user_id, token_hash, parent_id, is_revoked, expires_at
                FROM refresh_tokens
                WHERE token_hash = %s
                """,
                (token_hash,),
            )
            row = await cur.fetchone()

    if not row:
        return None
    return RefreshTokenRecord(
        id=str(row[0]),
        user_id=str(row[1]),
        token_hash=row[2],
        parent_id=str(row[3]) if row[3] else None,
        is_revoked=row[4],
        expires_at=row[5],
    )


async def revoke_refresh_token(token_id: str, token_hash: str) -> None:
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE refresh_tokens SET is_revoked = TRUE WHERE id = %s",
                (token_id,),
            )
    db.memcache_pool.delete(_rt_cache_key(token_hash))


async def revoke_all_user_tokens(user_id: str) -> None:
    """
    Revoke every active token for a user.
    Called on token-reuse detection (refresh token theft indicator).
    Memcache entries will be rejected on DB re-check or expire naturally.
    """
    async with db.postgres_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE refresh_tokens
                SET is_revoked = TRUE
                WHERE user_id = %s AND is_revoked = FALSE
                """,
                (user_id,),
            )