from pydantic import BaseModel, field_validator
from datetime import datetime
from enum import Enum


class Tier(Enum):
    FREE = "free"
    PRO = "pro"

class JWT_payload(BaseModel):
    sub: int
    tier: Tier
    exp: datetime
    iat: datetime

    @field_validator("exp", mode="after")
    @classmethod
    def validate_exp(cls, value):
        if value <= datetime.now():
            raise ValueError("Token expired")
        return value

class AccessToken(BaseModel):
    access_token: str
    token_type: str = "Bearer"