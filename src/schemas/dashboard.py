from pydantic import BaseModel

class DashboardSummaryStats(BaseModel):
    total_logs: int
    total_alerts: int  # Total number of alerts ever created
    active_alerts: int # Number of alerts currently in "Open" status
    anomalies_detected: int

    class Config:
        from_attributes = True