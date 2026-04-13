"""
jwt_provider.py
JWT creation / verification and the FastAPI protected-route dependency.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
from pydantic import BaseModel

import jwt
from fastapi import Depends, HTTPException, status, Response, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from utility.Setting import settings
from security.db_provider import (
    get_refresh_token,
    get_user_by_id,
    store_refresh_token,
    revoke_refresh_token,
    revoke_all_user_tokens
)

_bearer = HTTPBearer()

ALGORITHM = settings.JWT_ALGORITHM
SECRET = settings.JWT_SECRET_KEY


@dataclass
class TokenPayload:
    user_id: str
    tier: str
    exp: datetime

class RefreshRequest(BaseModel):
    refresh_token: str

# Token creation
def _create_access_token(user_id: str, tier: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(seconds=settings.JWT_ACCESS_TOKEN_EXP)
    payload = {"sub": user_id, "tier": tier, "exp": exp}
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def _create_refresh_token() -> str:
    """Return a cryptographically-secure opaque random token (URL-safe, 48 bytes)."""
    return secrets.token_urlsafe(48)

async def refresh_tokens(request: RefreshRequest, response: Response):
    record = await get_refresh_token(request.refresh_token)

    now = datetime.now(timezone.utc)

    if record is None or record.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid or expired.",
        )

    if record.is_revoked:
        # A revoked token was presented → possible token theft.
        # Revoke the entire token family for this user.
        await revoke_all_user_tokens(record.user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid or expired.",
        )

    user = await get_user_by_id(record.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )

    # Rotate: revoke old token, issue new pair
    await revoke_refresh_token(record.id, record.token_hash)
    return await issue_token_pair(user.id, user.tier_slug, response, parent_id=record.id)

async def issue_token_pair(
    user_id: str, tier: str, response: Response, parent_id: str | None = None
):
    access = _create_access_token(user_id, tier)
    refresh = _create_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.JWT_REFRESH_TOKEN_LONG_EXP
    )
    await store_refresh_token(user_id, refresh, expires_at, parent_id=parent_id)
    
    response.headers["Authorization"] = f"Bearer {access}"
    response.set_cookie(
        key="refresh_token",
        value=refresh,
        httponly=True,
        secure=True,
        max_age=settings.JWT_REFRESH_TOKEN_SHORT_EXP,
        samesite="lax"
    )

# Token verification
def verify_access_token(request: Request) -> TokenPayload:
    try:
        data = jwt.decode(request.headers["Authorization"], SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: Optional[str] = data.get("sub")
    tier: Optional[str] = data.get("tier")
    if not user_id or not tier:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
        )

    return TokenPayload(
        user_id=user_id,
        tier=tier,
        exp=datetime.fromtimestamp(data["exp"], tz=timezone.utc),
    )

# FastAPI dependency
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> TokenPayload:
    """
    Use as a dependency on any protected route:

        @router.get("/me")
        async def me(user: TokenPayload = Depends(get_current_user)):
            ...
    """
    return verify_access_token(credentials.credentials)


async def require_pro(
    user: TokenPayload = Depends(get_current_user),
) -> TokenPayload:
    """Dependency that additionally enforces the 'pro' tier."""
    if user.tier != "pro":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pro subscription required.",
        )
    return user