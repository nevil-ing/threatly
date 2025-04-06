# app/models/alert.py
from sqlalchemy import Column, Integer, DateTime, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base 

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("logs.id")) # Foreign key to logs table
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    severity = Column(String)
    description = Column(String)

    log = relationship("Log", backref="alerts") # Relationship to Log model (optional, for easy access to related log)