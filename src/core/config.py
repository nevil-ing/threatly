# src/core/config.py
from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv
from pathlib import Path


env_path = Path(__file__).resolve().parent.parent.parent / ".env" # More robust path
load_dotenv(dotenv_path=env_path) # Keep for local dev if needed

class Settings(BaseSettings):
    DATABASE_URL: str 
    
    # These are still useful if other parts of your app need them directly
    # or for consistency with the .env file structure.
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "sentinel_xdr_db") # Provide defaults if helpful
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "user")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "password")
    APACHE_ACCESS_LOG_PATH: str = os.getenv("APACHE_ACCESS_LOG_PATH", "/var/log/apache2/access_log")

settings = Settings()