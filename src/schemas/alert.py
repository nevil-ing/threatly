# app/schemas/alert.py
from typing import Optional
from datetime import datetime
from pydantic import BaseModel

class AlertBase(BaseModel):
    log_id: int 
    timestamp: datetime = datetime.now() 
    severity: str
    description: str

class AlertCreate(AlertBase):
    pass

class AlertUpdate(AlertBase):
    id: int

class AlertInDBBase(AlertBase):
    id: int

    class Config:
        from_attributes = True

class Alert(AlertInDBBase):
    pass