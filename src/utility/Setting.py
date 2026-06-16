from pydantic_settings import BaseSettings
from pydantic import SecretStr
from dotenv import load_dotenv

load_dotenv()

class Setting(BaseSettings):
    # app
    DOMAIN_HOST: str = "localhost:8080"

    # postgres
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str   = "my_db"
    POSTGRES_USER: str = "my_user"

    # memcached
    MEMCACHED_HOST: str = "memcached"
    MEMCACHED_PORT: int = 11211

    # JWT
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_HASH_ALGO: str = "sha256"
    JWT_ACCESS_TOKEN_EXP: int = 15              # minutes 
    JWT_REFRESH_TOKEN_LONG_EXP: int = 30        # days
 
    # Google Oauth
    GOOGLE_CLIENT_ID: SecretStr
    GOOGLE_CLIENT_SECRET: SecretStr

    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    OAUTH_STATE_TTL: int = 300      # seconds (5 min)
 
    # Rate limiting
    RATE_LIMIT_LOGIN: int = 5       # max attempts per window
    RATE_LIMIT_SIGNUP: int = 3
    RATE_LIMIT_WINDOW: int = 60     # window in seconds

settings = Setting()