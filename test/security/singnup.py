"""
signup.py
Email + password registration.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import HTTPException, status
from pydantic import BaseModel

from security.db_provider import (
    create_user_with_credential,
    enforce_rate_limit,
    get_user_by_email,
    store_refresh_token,
)
from security.jwt_provider import 
from utility.Setting import settings

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PASSWORD_MIN_LEN = 8


# ─────────────────────────────────────────────
# Request / Response schemas
# ─────────────────────────────────────────────

class SignupRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ─────────────────────────────────────────────
# Business logic
# ─────────────────────────────────────────────

async def signup(request: SignupRequest, client_ip: str) -> TokenPair:
    # Rate limit (keyed on IP to prevent burst registrations)
    enforce_rate_limit(
        client_ip,
        "signup",
        limit=settings.RATE_LIMIT_SIGNUP,
        window=settings.RATE_LIMIT_WINDOW,
    )

    # Validate email format
    if not _EMAIL_RE.match(request.email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid email address.",
        )

    # Validate password length
    if len(request.password) < _PASSWORD_MIN_LEN:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must be at least {_PASSWORD_MIN_LEN} characters.",
        )

    # Prevent duplicate registrations
    existing = await get_user_by_email(request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    # Hash password – bcrypt auto-generates a per-password salt
    password_hash = bcrypt.hashpw(
        request.password.encode(), bcrypt.gensalt()
    ).decode()

    # Persist user + credential atomically
    user = await create_user_with_credential(request.email, password_hash, name=request.name)

    # Issue token pair
    access = create_access_token(user.id, user.tier_slug)
    refresh = create_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.JWT_REFRESH_TOKEN_LONG_EXP
    )
    await store_refresh_token(user.id, refresh, expires_at)

    return TokenPair(access_token=access, refresh_token=refresh)