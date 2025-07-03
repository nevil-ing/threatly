
from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv
from pathlib import Path


env_path = Path(__file__).resolve().parent.parent.parent / ".env" 
load_dotenv(dotenv_path=env_path) 

class Settings(BaseSettings):
    DATABASE_URL: str 
    
 
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "sentinel_xdr_db") 
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "user")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "password")
    APACHE_ACCESS_LOG_PATH: str = os.getenv("APACHE_ACCESS_LOG_PATH", "/var/log/apache2/access_log")

settings = Settings()