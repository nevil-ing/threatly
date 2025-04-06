from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    POSTGRES_DB: str = os.getenv("POSTGRES_DB")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
    APACHE_ACCESS_LOG_PATH: str = os.getenv("APACHE_ACCESS_LOG_PATH", "/var/log/apache2/access_log")
    

    @property
    def DATABASE_URL(self) -> str:
    
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@db:5432/{self.POSTGRES_DB}"
    
    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()