from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

from src.core.database import Base

# Association table for incident-alert many-to-many relationship
incident_alert_association = Table(
    'incident_alerts',
    Base.metadata,
    Column('incident_id', Integer, ForeignKey('incidents.id'), primary_key=True),
    Column('alert_id', Integer, ForeignKey('alerts.id'), primary_key=True)
)

class IncidentStatus(enum.Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    CONTAINED = "Contained"
    RESOLVED = "Resolved"
    CLOSED = "Closed"

class IncidentSeverity(enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ActionStatus(enum.Enum):
    PENDING = "Pending"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=False)
    incident_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    priority = Column(String(10), nullable=False, index=True)
    status = Column(String(20), nullable=False, default=IncidentStatus.OPEN.value, index=True)
    
    # Assignment and ownership
    created_by = Column(String(100), nullable=False, index=True)
    assigned_to = Column(String(100), nullable=True, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    first_response_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    
    # Business impact
    affected_systems = Column(Text, nullable=True)
    business_impact = Column(Text, nullable=True)
    estimated_cost = Column(Float, nullable=True)
    
    # SLA tracking
    sla_breached = Column(Boolean, default=False, nullable=False)
    response_sla_minutes = Column(Integer, nullable=True)
    resolution_sla_hours = Column(Integer, nullable=True)
    
    # Resolution details
    resolution_summary = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    lessons_learned = Column(Text, nullable=True)
    
    # Relationships
    actions = relationship("IncidentAction", back_populates="incident", cascade="all, delete-orphan")
    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    alerts = relationship("Alert", secondary=incident_alert_association, back_populates="incidents")

class IncidentAction(Base):
    __tablename__ = "incident_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    
    action_type = Column(String(50), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default=ActionStatus.PENDING.value, index=True)
    priority = Column(String(20), nullable=False, index=True)
    
    # Assignment
    created_by = Column(String(100), nullable=False)
    assigned_to = Column(String(100), nullable=True, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    due_date = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Additional details
    notes = Column(Text, nullable=True)
    
    # Relationships
    incident = relationship("Incident", back_populates="actions")

class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    
    event_type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    created_by = Column(String(100), nullable=False)
    
    # JSON metadata for additional event details
    metadata = Column(Text, nullable=True)  # Store JSON as text
    
    # Relationships
    incident = relationship("Incident", back_populates="timeline")
