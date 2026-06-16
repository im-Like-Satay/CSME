"""
All the functions related to JWT
"""

from fastapi import HTTPException, status, Response, Request
from asyncpg import Connection

from jwt import encode, decode, InvalidSignatureError
from uuid_utils import uuid7
from secrets import token_hex
import hashlib

from pydantic import ValidationError
from datetime import datetime, timedelta

from utility.setting import settings
from security.schema import JWT_payload, Tier, AccessToken
from security.DB.jwt_db import db_create_refresh_token, db_rotate_refresh_token, db_revoke_all_tokens_for_device


def _credentials_exception(msg:str = "Could not validate credentials"):
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=msg,
        headers={"WWW-Authenticate": "Bearer"},
    )

def _create_access_token(user_id: int, tier: Tier):
    payload = JWT_payload(
        sub=user_id,
        tier=tier,
        exp=datetime.now() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXP),
        iat=datetime.now(),
    ).model_dump()
    return encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)

def _create_refresh_token():
    """refresh_token, hash_refresh_token = _create_refresh_token()"""

    refresh_token = token_hex(32)
    hash_refresh_token = hashlib.new(settings.JWT_ACCESS_TOKEN_HASH_ALGO, refresh_token.encode())
    return refresh_token, hash_refresh_token.hexdigest()

def _verify_access_token(token) -> JWT_payload:
    try:
        payload = decode(token, settings.JWT_SECRET_KEY.get_secret_value(), algorithms=[settings.JWT_ALGORITHM])
        return JWT_payload(**payload)
    except ValidationError:
        _credentials_exception("Invalid token")
    except InvalidSignatureError:
        _credentials_exception("Invalid token")


async def create_rotate_token_pair(
    conn: Connection, 
    user_id: int, 
    old_access_token, 
    tier: Tier, 
    response: Response, 
    device_fingerprint: str, 
    after_login: bool = False
) -> AccessToken:
    """
    Create new access and refresh tokens (store in cookie)
    use postgres for storing the refresh tokens
    """

    access_token = _create_access_token(user_id, tier)
    refresh_token, hash_refresh_token = _create_refresh_token()

    created_at = datetime.now()
    expires_at = created_at + timedelta(days=settings.JWT_REFRESH_TOKEN_SHORT_EXP)
    if after_login:
        login_at = datetime.now()
        session_expires_at = login_at + timedelta(days=settings.JWT_REFRESH_TOKEN_LONG_EXP)
        
        await db_create_refresh_token(
            conn=conn,
            user_id=user_id,
            device_fingerprint=device_fingerprint,
            token_hash=hash_refresh_token,
            
            login_at=login_at,
            session_expires_at=session_expires_at,
            created_at=created_at,
            expires_at=expires_at,
        )
    
    else:
        await db_rotate_refresh_token(
            conn=conn,
            old_token_id=old_access_token,
            new_token_hash=hash_refresh_token,
            new_expires_at=expires_at
        )

    response.set_cookie("refresh_token", refresh_token, httponly=True, secure=True, max_age=settings.JWT_REFRESH_TOKEN_SHORT_EXP, samesite="lax")
    return AccessToken(access_token)
    
