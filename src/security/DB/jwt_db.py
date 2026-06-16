"""
All database and cache access for the security module.
"""

import asyncpg
from datetime import datetime
from uuid_utils import uuid7
from uuid import UUID


async def db_create_refresh_token(
    conn: asyncpg.Connection,
    *,
    user_id: UUID,
    device_fingerprint: bytes,
    token_hash: bytes,

    expires_at: datetime,
    created_at: datetime,
    session_expires_at: datetime,
    login_at: datetime,
    
    replaced_by: UUID | None = None,
) -> asyncpg.Record:
    """
    Insert a new refresh token row.

    Used for:
      - First token after login
      - Token rotation (replaced_by=previous token id, login_at=original login_at)

    Returns the newly created record.
    """
    return await conn.fetchrow(
        """
        INSERT INTO refresh_tokens (
            id,
            user_id,
            replaced_by,
            device_fingerprint,
            token_hash,
            session_expires_at,
            expires_at,
            login_at,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        """,
        uuid7(),
        user_id,
        replaced_by,
        device_fingerprint,
        token_hash,         
        session_expires_at,
        expires_at,
        login_at,
        created_at,
    )


async def db_rotate_refresh_token(
    conn: asyncpg.Connection,
    *,
    old_token_id: UUID,
    new_token_hash: bytes,
    new_created_at: datetime,
    new_expires_at: datetime,
) -> asyncpg.Record | None:
    """
    Rotate a refresh token:
      1. Revoke the old token and mark it as replaced.

    Returns the new token record, or None if the old token was not found /
    already revoked / expired.

    The entire operation runs inside a single serializable transaction so
    concurrent rotation attempts are safe — only the first caller wins.
    """

    new_token_id = uuid7()
    async with conn.transaction(isolation="serializable"):
        # Lock + validate the old token atomically
        old = await conn.fetchrow(
            """
            SELECT
                id,
                user_id,
                device_fingerprint,
                login_at,
                session_expires_at,
                is_revoked,
                expires_at,
                replaced_by
            FROM refresh_tokens
            WHERE id = $1
            FOR UPDATE
            """,
            old_token_id,
        )

        if old is None:
            return None  # token not found

        if old["is_revoked"]:
            return None  # already revoked (possible replay attack)

        if old["replaced_by"] is not None:
            return None  # already rotated

        now = datetime.now(tz=old["expires_at"].tzinfo)
        if old["expires_at"] < now:
            return None  # token expired

        if old["session_expires_at"] < now:
            return None  # session expired — user must re-login

        # Revoke the old token and record which token replaces it
        await conn.execute(
            """
            UPDATE refresh_tokens
            SET is_revoked  = TRUE,
                replaced_by = $2
            WHERE id = $1
            """,
            old_token_id,
            new_token_id,
        )

        # Insert the rotated token, inheriting session context from the old one
        new = await conn.fetchrow(
            """
            INSERT INTO refresh_tokens (
                id,
                user_id,
                replaced_by,
                device_fingerprint,
                token_hash,
                login_at,
                session_expires_at,
                expires_at,
                created_at
            )
            VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8)
            RETURNING *
            """,
            new_token_id,
            old["user_id"],
            old["device_fingerprint"],
            new_token_hash,
            old["login_at"],
            old["session_expires_at"],
            new_expires_at,
            new_created_at,
        )

    return new


# ---------------------------------------------------------------------------
# Lookup / validation
# ---------------------------------------------------------------------------


async def db_get_active_token_by_user_and_device(
    conn: asyncpg.Connection,
    *,
    user_id: UUID,
    device_fingerprint: bytes,
) -> asyncpg.Record | None:
    """
    Return the current active (not revoked, not expired, not yet rotated)
    refresh token for a given user + device fingerprint, or None.

    "Active" means:
      - is_revoked = FALSE
      - replaced_by IS NULL  (it is the leaf / latest token in the chain)
      - expires_at > NOW()
      - session_expires_at > NOW()
    """
    return await conn.fetchrow(
        """
        SELECT *
        FROM refresh_tokens
        WHERE user_id            = $1
          AND device_fingerprint = $2
          AND is_revoked         = FALSE
          AND replaced_by        IS NULL
          AND expires_at         > CURRENT_TIMESTAMP
          AND session_expires_at > CURRENT_TIMESTAMP
        LIMIT 1
        """,
        user_id,
        device_fingerprint,
    )


async def db_token_exists_for_user_and_device(
    conn: asyncpg.Connection,
    *,
    user_id: UUID,
    device_fingerprint: bytes,
) -> bool:
    """
    Return True if any (active or not) refresh token exists for this
    user + device pair. Useful for deciding whether to create a first
    token vs. rotate an existing chain.
    """
    row = await conn.fetchrow(
        """
        SELECT 1
        FROM refresh_tokens
        WHERE user_id            = $1
          AND device_fingerprint = $2
        LIMIT 1
        """,
        user_id,
        device_fingerprint,
    )
    return row is not None


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


async def db_delete_old_token_generations(
    conn: asyncpg.Connection,
    *,
    user_id: UUID,
    device_fingerprint: bytes,
    keep_generations: int = 4,
) -> int:
    """
    Delete revoked ancestor tokens that are more than `keep_generations`
    steps behind the current live token for a given user + device.

    Strategy:
      - Walk the replaced_by chain from the current leaf token backwards.
      - Keep the most recent `keep_generations` tokens (including the live one).
      - Delete everything older (they are already revoked and superseded).

    Returns the number of deleted rows.

    Why keep a few generations?
      Retaining a small history window lets you detect token-reuse attacks
      (a revoked token being presented again) without keeping the full chain
      forever.
    """
    deleted: int = await conn.fetchval(
        """
        WITH RECURSIVE token_chain AS (
            -- Start from the current live token (leaf of the chain)
            SELECT
                id,
                replaced_by,   -- NULL for the live token; non-NULL means "this was replaced by..."
                1 AS generation
            FROM refresh_tokens
            WHERE user_id            = $1
              AND device_fingerprint = $2
              AND replaced_by        IS NULL   -- live / current token
              AND is_revoked         = FALSE

            UNION ALL

            -- Walk backwards: find the token that was replaced by the current one
            -- i.e. find t such that t.replaced_by = chain.id  (parent of current)
            SELECT
                t.id,
                t.replaced_by,
                tc.generation + 1
            FROM refresh_tokens t
            INNER JOIN token_chain tc
                -- The parent is the token whose replaced_by points to the current chain node
                ON t.replaced_by = tc.id
            -- replaced_by on the parent points *forward* (to the newer token)
            -- but we're walking *backward*, so we join on t.replaced_by = tc.id
        ),
        to_delete AS (
            SELECT id
            FROM token_chain
            WHERE generation > $3   -- older than the keep window
        )
        DELETE FROM refresh_tokens
        WHERE id IN (SELECT id FROM to_delete)
        RETURNING id
        """,
        user_id,
        device_fingerprint,
        keep_generations,
    )
    # fetchval returns None when no rows are affected by RETURNING
    return deleted or 0


async def db_revoke_all_tokens_for_device(
    conn: asyncpg.Connection,
    *,
    user_id: UUID,
    device_fingerprint: bytes,
) -> int:
    """
    Revoke every token in the chain for a given user + device.
    Call this on explicit logout or suspected compromise.

    Returns the number of revoked rows.
    """
    result = await conn.execute(
        """
        UPDATE refresh_tokens
        SET is_revoked = TRUE
        WHERE user_id            = $1
          AND device_fingerprint = $2
          AND is_revoked         = FALSE
        """,
        user_id,
        device_fingerprint,
    )
    # asyncpg returns "UPDATE N" as a string
    return int(result.split()[-1])


async def db_revoke_all_tokens_for_user(
    conn: asyncpg.Connection,
    *,
    user_id: UUID,
) -> int:
    """
    Revoke every token across all devices for a user (e.g. password change,
    account compromise). Returns the number of revoked rows.
    """
    result = await conn.execute(
        """
        UPDATE refresh_tokens
        SET is_revoked = TRUE
        WHERE user_id  = $1
          AND is_revoked = FALSE
        """,
        user_id,
    )
    return int(result.split()[-1])