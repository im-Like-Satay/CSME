"""
router.py
FastAPI router for the security module.
Only imports and wires async functions – no business logic here.
"""
from __future__ import annotations

import secrets

import db
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from security.google_Oauth import get_google_auth_url, google_authenticate
from security.jwt_provider import TokenPayload, get_current_user
from security.login import LoginRequest, login, logout, refresh_tokens
from security.signup import SignupRequest, signup

router = APIRouter(prefix="/security", tags=["security"])

_OAUTH_STATE_TTL = 600  # 10 minutes


# ── Signup ────────────────────────────────────────────────────

@router.post("/signup", status_code=201)
async def signup_endpoint(body: SignupRequest, request: Request):
    return await signup(body, request.client.host)


# ── Login ─────────────────────────────────────────────────────

@router.post("/login")
async def login_endpoint(body: LoginRequest, request: Request):
    return await login(body, request.client.host)


# ── Token refresh ─────────────────────────────────────────────

@router.post("/refresh")
async def refresh_endpoint(refresh_token: str = Cookie(...)):
    return await refresh_tokens(refresh_token)


# ── Logout ────────────────────────────────────────────────────

@router.post("/logout")
async def logout_endpoint(refresh_token: str = Cookie(...)):
    return await logout(refresh_token)


# ── Google OAuth ──────────────────────────────────────────────

@router.get("/google")
async def google_login():
    state = secrets.token_urlsafe(16)
    db.memcache_pool.set(f"oauth_state:{state}", b"1", expire=_OAUTH_STATE_TTL)
    return RedirectResponse(get_google_auth_url(state))


@router.get("/google/callback")
async def google_callback(code: str, state: str):
    key = f"oauth_state:{state}"
    if not db.memcache_pool.get(key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state. Please try signing in again.",
        )
    db.memcache_pool.delete(key)
    return await google_authenticate(code)


# ── Protected route example ───────────────────────────────────

@router.get("/me")
async def me(user: TokenPayload = Depends(get_current_user)):
    return {"user_id": user.user_id, "tier": user.tier}