from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models.log import Log
from src.models.alert import Alert
from src.schemas.dashboard import DashboardSummaryStats # Import the new schema

router = APIRouter()

@router.get(
    "dashboard/summary-stats",
    response_model=DashboardSummaryStats,
    tags=["Dashboard"],
    summary="Get summary statistics for the dashboard"
)
async def get_dashboard_summary_stats(db: Session = Depends(get_db)):
    """
    Provides aggregated statistics for the main dashboard, including
    total logs, total alerts, active (open) alerts, and anomalies detected.
    """
    total_logs = db.query(Log).count()
    total_alerts = db.query(Alert).count()
    # Assuming 'Open' is the status string for active alerts as per Alert model
    active_alerts = db.query(Alert).filter(Alert.status == "Open").count()
    anomalies_detected = db.query(Log).filter(Log.is_anomaly == True).count()

    return DashboardSummaryStats(
        total_logs=total_logs,
        total_alerts=total_alerts,
        active_alerts=active_alerts,
        anomalies_detected=anomalies_detected
    )