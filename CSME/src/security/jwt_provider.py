"""
All the functions related to JWT
"""

from fastapi import HTTPException, status
from jwt import encode, decode, InvalidSignatureError
from secrets import token_hex
import hashlib

from pydantic import ValidationError
from datetime import datetime, timedelta

from utility.Setting import settings
from security.schema import JWT_payload, Tier


def _credentials_exception(msg:str = "Could not validate credentials"):
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=msg,
        headers={"WWW-Authenticate": "Bearer"},
    )

def create_access_token(user_id: int, tier: Tier):
    payload = JWT_payload(
        sub=user_id,
        tier=tier,
        exp=datetime.now() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXP),
        iat=datetime.now(),
    ).model_dump()
    return encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)

def create_refresh_token():
    """access_token, hash_access_token = _create_refresh_token()"""

    refresh_token = token_hex(32)
    hash_refresh_token = hashlib.new(settings.JWT_ACCESS_TOKEN_HASH_ALGO, refresh_token.encode())
    return refresh_token, hash_refresh_token.hexdigest()

def _verify_access_token(token: str) -> JWT_payload:
    try:
        payload = decode(token, settings.JWT_SECRET_KEY.get_secret_value(), algorithms=[settings.JWT_ALGORITHM])
        return JWT_payload(**payload)
    except ValidationError:
        _credentials_exception("Invalid token")
    except InvalidSignatureError:
        _credentials_exception("Invalid token")