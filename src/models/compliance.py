from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from src.core.database import Base


class ReportStatus(str, enum.Enum):
    PENDING = "Pending"
    PROCESSING = "Processing"
    COMPLETED = "Completed"
    FAILED = "Failed"

class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    
    # Framework and Status
    framework = Column(String(50), nullable=False, index=True)  # e.g., "GDPR", "ISO27001"
    status = Column(Enum(ReportStatus), default=ReportStatus.PENDING, nullable=False, index=True)
    
    # Results
    is_violation = Column(Boolean, nullable=True) # Nullable until analysis is complete
    summary = Column(Text, nullable=True) # High-level summary from the LLM
    violation_details = Column(Text, nullable=True) # Specific details about the violation
    recommended_actions = Column(Text, nullable=True) # Actions suggested by the LLM
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True) # When the analysis finished
    
    # Relationships
    alert = relationship("Alert")