"""
login.py
Email + password login, token refresh, and logout.
"""

import bcrypt
from fastapi import HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm

from security.db_provider import (
    enforce_rate_limit,
    get_password_hash,
    get_refresh_token,
    get_user_by_email,
    revoke_refresh_token
)
from security.jwt_provider import issue_token_pair
from utility.Setting import settings




# ─────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────

async def login(response: Response, login_request: LoginRequest, client_ip: str):
    # Rate limit on IP; also consider keying on email for targeted brute-force
    enforce_rate_limit(
        client_ip,
        "login",
        limit=settings.RATE_LIMIT_LOGIN,
        window=settings.RATE_LIMIT_WINDOW,
    )

    user = await get_user_by_email(login_request.email)

    # Intentionally use the same error message for unknown email and wrong
    # password to avoid user-enumeration.
    _creds_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password.",
    )

    if user is None:
        # Still run bcrypt to keep constant-time behaviour
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        raise _creds_error

    password_hash = await get_password_hash(user.id)
    if password_hash is None:
        # OAuth-only account – no password set
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This account uses social login. Please sign in with Google.",
        )

    if not bcrypt.checkpw(login_request.password.encode(), password_hash.encode()):
        raise _creds_error

    return await issue_token_pair(user.id, user.tier_slug, response)


# ─────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────

async def logout(request: LogoutRequest) -> dict:
    record = await get_refresh_token(request.refresh_token)
    if record and not record.is_revoked:
        await revoke_refresh_token(record.id, record.token_hash)
    # Always return success to avoid leaking information
    return {"detail": "Logged out successfully."}