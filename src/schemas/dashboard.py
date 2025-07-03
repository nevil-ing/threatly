from pydantic import BaseModel

class DashboardSummaryStats(BaseModel):
    total_logs: int
    total_alerts: int  
    active_alerts: int 
    anomalies_detected: int

    class Config:
        from_attributes = True