from sqlalchemy import Boolean, Column, Integer, DateTime, String, JSON, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.core.database import Base

class ProcessedLog(Base):
    __tablename__="processed_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source_type = Column(String, index=True)
    source_ip = Column(String, nullable=True)
    data = Column(JSON)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    threat_type = Column(String, nullable=True, default = "Normal")