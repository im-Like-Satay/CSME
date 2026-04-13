"""
google_Oauth.py
Google OAuth 2.0 authorization-code flow.
"""

from dataclasses import dataclass

import httpx
from fastapi import HTTPException, status

from security.db_provider import (
    create_user_with_oauth,
    get_oauth_user,
    get_user_by_email,
    link_oauth_to_existing_user
)
from security.jwt_provider import issue_token_pair
from utility.Setting import settings

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

PROVIDER = "google"


# ─────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────

@dataclass
class GoogleUserInfo:
    provider_user_id: str   # Google's 'sub'
    email: str
    name: str
    email_verified: bool


# ─────────────────────────────────────────────
# Step 1 – build redirect URL
# ─────────────────────────────────────────────

def get_google_auth_url(state: str) -> str:
    """
    Build the Google consent-screen URL.
    `state` should be a CSRF token generated per-request (e.g. secrets.token_urlsafe()).
    """
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": state,
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{_GOOGLE_AUTH_URL}?{query}"


# ─────────────────────────────────────────────
# Step 2 – exchange code for user info
# ─────────────────────────────────────────────

async def exchange_code_for_user(code: str) -> GoogleUserInfo:
    """Exchange an authorization code for Google user info."""
    async with httpx.AsyncClient() as client:
        # Exchange code → tokens
        token_resp = await client.post(
            _GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )
        if token_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to exchange Google authorization code.",
            )
        google_tokens = token_resp.json()

        # Fetch user profile
        userinfo_resp = await client.get(
            _GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {google_tokens['access_token']}"},
        )
        if userinfo_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to retrieve Google user info.",
            )
        info = userinfo_resp.json()

    if not info.get("email_verified", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account email is not verified.",
        )

    return GoogleUserInfo(
        provider_user_id=info["sub"],
        email=info["email"],
        name=info.get("name", ""),
        email_verified=info["email_verified"],
    )


# ─────────────────────────────────────────────
# Step 3 – find or create user, issue tokens
# ─────────────────────────────────────────────

async def google_authenticate(code: str) -> TokenPair:
    """
    Full OAuth flow: exchange code → get user info → find/create user → issue tokens.
    """
    google_user = await exchange_code_for_user(code)

    # Try to find an existing OAuth link
    user = await get_oauth_user(PROVIDER, google_user.provider_user_id)

    if user is None:
        # No existing OAuth link.  Check if the email already exists (password user).
        existing = await get_user_by_email(google_user.email)
        if existing:
            # Link Google to the existing account
            await link_oauth_to_existing_user(
                existing.id, PROVIDER, google_user.provider_user_id
            )
            user = existing
        else:
            # Brand-new user
            user = await create_user_with_oauth(
                google_user.email, PROVIDER, google_user.provider_user_id,
                name=google_user.name or None,
            )

    return await issue_token_pair(user.id, user.tier_slug)