from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.alert import  Alert
from app.services.alerting import trigger_alert
from typing import List


router = APIRouter()


# get alerts list
@router.get("/alerts/", response_model=Alert)
def get_alert(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieve a list of alerts.
    
    """
    alerts = db.query(Alert).offset(skip).limit(limit).all()

    return alerts

# get alert by id
@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert_by_id(alert_id: int,db: Session = Depends(get_db)):
    """
    Retrieve an alert by ID.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    return alert