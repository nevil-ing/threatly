from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, Float
from sqlalchemy.orm import relationship
from src.core.database import Base
from datetime import datetime

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("logs.id"), nullable=False)
    threat_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # Critical, High, Medium, Low
    status = Column(String(20), default="Open", index=True)  # Open, Investigating, Resolved, False Positive
    description = Column(Text, nullable=False)
    confidence_score = Column(String(10), nullable=True)  # Store as string for flexibility
    matched_patterns = Column(Text, nullable=True)  # JSON string of matched patterns
    source_ip = Column(String(45), nullable=True, index=True)  # IPv4/IPv6 support
    source_type = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    assigned_to = Column(String(100), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    # Relationships
    log = relationship("Log", back_populates="alerts")
    
    def __repr__(self):
        return f"<Alert(id={self.id}, threat_type='{self.threat_type}', severity='{self.severity}', status='{self.status}')>"
