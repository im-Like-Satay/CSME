from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Setting(BaseSettings):
    # postgres
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str   = "my_db"
    POSTGRES_USER: str = "my_user"

    # memcached
    MEMCACHED_HOST: str = "memcached"
    MEMCACHED_PORT: int = 11211
