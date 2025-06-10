from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class IncidentStatus(str, Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    CONTAINED = "Contained"
    RESOLVED = "Resolved"
    CLOSED = "Closed"

class IncidentSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ActionStatus(str, Enum):
    PENDING = "Pending"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"

# Base schemas
class IncidentBase(BaseModel):
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=10)
    incident_type: str
    severity: IncidentSeverity
    priority: str = Field(..., pattern="^P[1-4]$")
    assigned_to: Optional[str] = None
    affected_systems: Optional[str] = None
    business_impact: Optional[str] = None
    estimated_cost: Optional[float] = None

class IncidentCreate(IncidentBase):
    created_by: Optional[str] = None
    alert_ids: Optional[List[int]] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=5, max_length=200)
    description: Optional[str] = Field(None, min_length=10)
    incident_type: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    priority: Optional[str] = Field(None, pattern="^P[1-4]$")
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    affected_systems: Optional[str] = None
    business_impact: Optional[str] = None
    estimated_cost: Optional[float] = None

class IncidentResponse(IncidentBase):
    id: int
    status: IncidentStatus
    created_at: datetime
    updated_at: Optional[datetime] = None
    first_response_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    created_by: str
    sla_breached: bool = False
    response_sla_minutes: Optional[int] = None
    resolution_sla_hours: Optional[int] = None
    
    class Config:
        from_attributes = True

# Action schemas
class IncidentActionBase(BaseModel):
    action_type: str
    title: str = Field(..., min_length=5, max_length=200)
    description: str
    priority: str = Field(..., pattern="^(Low|Medium|High|Critical)$")
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None

class IncidentActionCreate(IncidentActionBase):
    created_by: Optional[str] = None

class IncidentActionUpdate(BaseModel):
    action_type: Optional[str] = None
    title: Optional[str] = Field(None, min_length=5, max_length=200)
    description: Optional[str] = None
    status: Optional[ActionStatus] = None
    priority: Optional[str] = Field(None, pattern="^(Low|Medium|High|Critical)$")
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    notes: Optional[str] = None

class IncidentActionResponse(IncidentActionBase):
    id: int
    incident_id: int
    status: ActionStatus
    created_at: datetime
    completed_at: Optional[datetime] = None
    created_by: str
    notes: Optional[str] = None
    
    class Config:
        from_attributes = True

# Timeline schemas
class IncidentTimelineBase(BaseModel):
    event_type: str
    description: str
    metadata: Optional[Dict[str, Any]] = None

class IncidentTimelineCreate(IncidentTimelineBase):
    created_by: Optional[str] = None

class IncidentTimelineResponse(IncidentTimelineBase):
    id: int
    incident_id: int
    created_at: datetime
    created_by: str
    
    class Config:
        from_attributes = True

# Detailed incident response
class IncidentDetails(IncidentResponse):
    actions: List[IncidentActionResponse] = []
    timeline: List[IncidentTimelineResponse] = []
    related_alerts: List[Dict[str, Any]] = []
    resolution_summary: Optional[str] = None
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None

# Statistics schema
class IncidentStats(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_incidents: int
    avg_resolution_time_hours: float
    sla_breach_rate: float
    incidents_by_type: Dict[str, int]
    incidents_by_severity: Dict[str, int]
    recent_incidents: List[IncidentResponse]
