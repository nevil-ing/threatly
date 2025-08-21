from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class ProcessedLogBase(BaseModel):
    timestamp: datetime
    source_type: str
    source_ip: Optional[str] = None
    data: Dict[str, Any]
    is_anomaly: bool = False
    anomaly_score: Optional[float] = None
    threat_type: Optional[str] = None

class LogCreate(ProcessedLogBase):
    pass

class LogUpdate(ProcessedLogBase):
    id: int

class LogInDBBase(ProcessedLogBase):
    id: int

    class Config:
        from_attributes = True   

class Log(ProcessedLogInDBBase):
    pass