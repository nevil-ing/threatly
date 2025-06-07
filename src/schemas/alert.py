from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AlertBase(BaseModel):
    threat_type: str
    severity: str
    description: str
    confidence_score: Optional[str] = None
    source_ip: Optional[str] = None
    source_type: Optional[str] = None

class AlertCreate(AlertBase):
    log_id: int
    matched_patterns: Optional[str] = None

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None

class AlertResponse(AlertBase):
    id: int
    log_id: int
    status: str
    matched_patterns: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None
    
    class Config:
        from_attributes = True