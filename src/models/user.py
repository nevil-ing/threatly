rom sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, Float
from sqlalchemy.orm import relationship
from src.core.database import Base
from datetime import datetime

class User(Base):  
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    hash_password = Column(String(255), nullable=False)
    is_superuser = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)