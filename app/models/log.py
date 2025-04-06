# app/models/log.py
from sqlalchemy import Boolean, Column, Integer, DateTime, String, JSON, Float
from sqlalchemy.sql import func  # Import func for server_default

from app.core.database import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now()) # Using DateTime with timezone and server_default
    source_type = Column(String, index=True) #indexed for faster filtering
    source_ip = Column(String, nullable=True) #Allow null for optional IP
    data = Column(JSON) # Use JSON type for flexible data
    is_anomaly = Column(Boolean, default=False) #Boolean for true/false anomaly flag
    anomaly_score = Column(Float, nullable=True) #Float for anomaly score, allow null