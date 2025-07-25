from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class AlertSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class AlertStatus(str, Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"

class ThreatType(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS_ATTACK = "XSS Attack"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    BRUTE_FORCE = "Brute Force"
    DDOS = "DDoS"
    MALWARE = "Malware"
    DATA_EXFILTRATION = "Data Exfiltration"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    AUTHENTICATION_BYPASS = "Authentication Bypass"
    CSRF = "CSRF"
    XXE = "XXE"
    LDAP_INJECTION = "LDAP Injection"
    FILE_UPLOAD_ATTACK = "File Upload Attack"
    SUSPICIOUS_ACTIVITY = "Suspicious Activity"
    UNKNOWN_ANOMALY = "Unknown Anomaly"
    NORMAL = "Normal"

class AlertBase(BaseModel):
    threat_type: str = Field(..., description="Type of threat detected")
    severity: AlertSeverity = Field(..., description="Severity level of the alert")
    description: str = Field(..., min_length=10, description="Detailed description of the alert")
    confidence_score: Optional[str] = Field(None, description="Confidence score of the detection")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    source_type: Optional[str] = Field(None, description="Type of log source")

    @field_validator('threat_type')
    @classmethod
    def validate_threat_type(cls, v):
        if not v or v.strip() == "":
            raise ValueError('Threat type cannot be empty')
        return v.strip()

class AlertCreate(AlertBase):
    log_id: int = Field(..., gt=0, description="ID of the associated log entry")
    matched_patterns: Optional[str] = Field(None, description="JSON string of matched patterns")

class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = Field(None, description="New status for the alert")
    assigned_to: Optional[str] = Field(None, max_length=100, description="Person assigned to handle the alert")
    resolution_notes: Optional[str] = Field(None, description="Notes about the resolution")

    @field_validator('assigned_to')
    @classmethod
    def validate_assigned_to(cls, v):
        if v is not None and v.strip() == "":
            return None
        return v.strip() if v else None

class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    log_id: int
    status: AlertStatus
    matched_patterns: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None

# Add this new schema for paginated responses
class PaginatedAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    alerts: List[AlertResponse]
    total: int
    skip: int
    limit: int

class AlertSummary(BaseModel):
    """Summary model for dashboard and statistics"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    threat_type: str
    severity: AlertSeverity
    status: AlertStatus
    source_ip: Optional[str]
    created_at: datetime

class ThreatTypeSummary(BaseModel):
    """Summary of alerts by threat type"""
    threat_type: str
    total_count: int
    severity_breakdown: Dict[str, int]
    latest_alert: Optional[Dict[str, Any]] = None

class AlertStatistics(BaseModel):
    """Comprehensive alert statistics"""
    period_days: int
    total_alerts: int
    open_alerts: int
    threat_types: List[ThreatTypeSummary]
    generated_at: str

class DashboardStats(BaseModel):
    """Dashboard statistics model"""
    summary: Dict[str, Any]
    top_threat_types: List[Dict[str, Any]]
    recent_high_priority: List[Dict[str, Any]]
    daily_trend: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]
    period_days: int
    generated_at: str

# Bulk operations schemas
class BulkAlertUpdate(BaseModel):
    alert_ids: List[int] = Field(..., min_length=1, description="List of alert IDs to update")
    status: Optional[AlertStatus] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None

class BulkUpdateResponse(BaseModel):
    updated_count: int
    failed_count: int
    errors: List[str] = []