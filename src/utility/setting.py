from dotenv import load_dotenv
from pydantic import SecretStr
from pydantic_settings import BaseSettings

load_dotenv()


class Setting(BaseSettings):
    # app
    DOMAIN_HOST: str = "localhost:8080"

    # JWT
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_HASH_ALGO: str = "sha256"
    JWT_ACCESS_TOKEN_EXP: int = 15  # minutes
    JWT_REFRESH_TOKEN_SHORT_EXP: int = 5  # days
    JWT_REFRESH_TOKEN_LONG_EXP: int = 30  # days

    # Google Oauth
    GOOGLE_CLIENT_ID: SecretStr
    GOOGLE_CLIENT_SECRET: SecretStr

    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    OAUTH_STATE_TTL: int = 300  # seconds (5 min)


settings = Setting()
