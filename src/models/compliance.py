from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from src.core.database import Base

class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    log_id = Column(Integer, ForeignKey("logs.id"), nullable=True)

    compliance_type = Column(String(100))  # e.g. "GDPR", "ISO27001"
    input_data = Column(Text, nullable=False)  # Raw text analyzed
    result_summary = Column(Text)
    is_violation = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    alert = relationship("Alert", back_populates="compliance")
    log = relationship("Log")
