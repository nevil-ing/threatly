from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class ComplianceReportCreate(BaseModel):
    log_id: Optional[int]
    alert_id: Optional[int]
    compliance_type: Optional[str] = "General"
    input_data: str

class ComplianceReportRead(BaseModel):
    id: int
    log_id: Optional[int]
    alert_id: Optional[int]
    compliance_type: Optional[str]
    input_data: str
    result_summary: str
    is_violation: bool
    created_at: datetime

    class Config:
        orm_mode = True
