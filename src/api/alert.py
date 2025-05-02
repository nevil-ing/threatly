from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models import Alert


router = APIRouter()


@router.get("/alerts/", tags=["Alert"])
async def get_alerts(db: Session = Depends(get_db)):
    """Get all alerts"""
    db_alerts =db.query(Alert).all()
    if not db_alerts:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No alerts found")
    return db_alerts

@router.get("/alerts/{alert_id}", tags=["Alert"])
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get a Specific alert"""
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return db_alert
