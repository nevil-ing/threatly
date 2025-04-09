from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv
from pathlib import Path
from typing import ClassVar

env_path = Path('.') / ".env"
load_dotenv(dotenv_path=env_path)

class Settings(BaseSettings):
    POSTGRES_DB: str = os.getenv("POSTGRES_DB")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
    APACHE_ACCESS_LOG_PATH: str = os.getenv("APACHE_ACCESS_LOG_PATH", "/var/log/apache2/access_log")
    
    DATABASE_URL: ClassVar[str] = f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@db:5432/{os.getenv('POSTGRES_DB')}"

settings = Settings()
