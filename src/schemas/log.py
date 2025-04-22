from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class LogBase(BaseModel):
    timestamp: datetime
    source_type: str
    source_ip: Optional[str] = None
    data: Dict[str, Any]
    is_anomaly: bool = False
    anomaly_score: Optional[float] = None

class LogCreate(LogBase):
    pass

class LogUpdate(LogBase):
    id: int

class LogInDBBase(LogBase):
    id: int

    class Config:
        from_attributes = True   

class Log(LogInDBBase):
    pass