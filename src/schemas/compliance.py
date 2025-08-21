# src/schemas/compliance.py
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from src.models.compliance import ReportStatus # Import the enum

# --- Utility for camelCase ---
def to_camel(string: str) -> str:
    words = string.split('_')
    return words[0] + ''.join(word.capitalize() for word in words[1:])

# --- Schemas ---
class ComplianceReportBase(BaseModel):
    framework: str = Field(..., description="The compliance framework to analyze against (e.g., GDPR, ISO27001)")
    alert_id: int = Field(..., gt=0, description="The ID of the alert to analyze")

class ComplianceReportCreate(ComplianceReportBase):
    pass

class ComplianceReportResponse(ComplianceReportBase):
    id: int
    status: ReportStatus
    is_violation: Optional[bool] = None
    summary: Optional[str] = None
    violation_details: Optional[str] = None
    recommended_actions: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        orm_mode = True # For Pydantic v1
        alias_generator = to_camel
        allow_population_by_field_name = True

class BulkComplianceRequest(BaseModel):
    alert_ids: List[int] = Field(..., description="List of alert IDs to analyze")
    frameworks: List[str] = Field(..., description="List of frameworks to analyze against")

class ComplianceDashboardStats(BaseModel):
    period_days: int
    total_reports: int
    status_breakdown: Dict[str, int]
    violation_stats: Dict[str, int]
    framework_breakdown: Dict[str, int]
    recent_violations: List[Dict[str, Any]]

class ComplianceSummaryReport(BaseModel):
    framework: str
    period_days: int
    analysis_period: Dict[str, str]
    summary: Dict[str, Any]
    violation_analysis: Dict[str, Dict[str, int]]
    recent_violations: List[Dict[str, Any]]
    recommendations: List[str]

class FrameworkInfo(BaseModel):
    frameworks: List[str]
    descriptions: Dict[str, str]

class ComplianceTestResult(BaseModel):
    alert_id: int
    framework: str
    test_result: Dict[str, Any]
    timestamp: datetime

class ModelStatus(BaseModel):
    model_loaded: bool
    tokenizer_loaded: Optional[bool] = None
    device: Optional[str] = None
    model_name: Optional[str] = None
    cuda_available: Optional[bool] = None
    hf_token_configured: Optional[bool] = None
    error: Optional[str] = None
    status: Optional[str] = None