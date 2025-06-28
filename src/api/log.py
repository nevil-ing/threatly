from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models import Log  
from src.schemas import LogCreate, LogUpdate 
from src.services.anomaly_detector import LogAnomalyDetector
from src.services import storage_service 
import logging
import json

router = APIRouter()
anomaly_detector = LogAnomalyDetector()


@router.post("/logs/")
async def create_log(log: LogCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    
    db_log = storage_service.store_log(db=db, log_data=log)

    if not db_log:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store log entry in the database."
        )

    
    background_tasks.add_task(
        anomaly_detector.detect_anomaly,
        log_data=log.data,
        log_entry=db_log,
        db=db
    )
    
    return {"status": "Log received and scheduled for analysis", "log_id": db_log.id}


@router.get("/logs/", tags=["logs"])
async def read_all_logs(db: Session = Depends(get_db)):
    db_logs = db.query(Log).all()
    if not db_logs:
        raise HTTPException(status_code=404, detail="No logs found")
    return db_logs

@router.get("/logs/{log_id}")
async def read_log(log_id: int, db: Session = Depends(get_db)):
    db_log = db.query(Log).filter(Log.id == log_id).first()
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return db_log

@router.put("/logs/{log_id}")
async def update_log(log_id: int, log: LogUpdate, db: Session = Depends(get_db)):
    db_log = db.query(Log).filter(Log.id == log_id).first()
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    db_log.source_type = log.source_type
    db_log.source_ip = log.source_ip
    db_log.data = log.data
    db_log.is_anomaly = log.is_anomaly
    db_log.anomaly_score = log.anomaly_score
    db.commit()
    db.refresh(db_log)
    return {"status": "Log updated successfully", "log_id": db_log.id}

# New endpoints for anomaly detection

@router.get("/anomalies/", tags=["anomalies"])
async def get_anomalies(threshold: float = 0.5, limit: int = 100, db: Session = Depends(get_db)):
    """Get logs that are marked as anomalies or have an anomaly score above threshold"""
    db_logs = db.query(Log).filter(
        (Log.is_anomaly == True) | (Log.anomaly_score >= threshold)
    ).order_by(Log.timestamp.desc()).limit(limit).all()
    
    return db_logs

@router.post("/analyze-existing/", tags=["anomalies"])
async def analyze_existing_logs(background_tasks: BackgroundTasks, threshold: float = 0.5, db: Session = Depends(get_db)):
    """Analyze existing logs that haven't been evaluated for anomalies yet"""
    # This will be executed in the background
    background_tasks.add_task(analyze_logs_batch, threshold, db)
    return {"status": "Background analysis started"}

# Helper function for background processing
def analyze_logs_batch(threshold: float, db: Session):
    """Process logs with null anomaly_score in batches"""
    batch_size = 100
    offset = 0
    
    while True:
        # Get a batch of unanalyzed logs
        logs = db.query(Log).filter(Log.anomaly_score == None).limit(batch_size).offset(offset).all()
        
        if not logs:
            break
            
        for log in logs:
            try:
                # Pass the log entry and db session to enable alerting
                result = anomaly_detector.detect_anomaly(log.data, threshold, log_entry=log, db=db)
                # The anomaly_detector will handle updating the log and triggering alerts
                if not result['is_anomaly']:
                    # Only update if it's not an anomaly (anomalies are handled in detect_anomaly)
                    log.is_anomaly = result['is_anomaly']
                    log.anomaly_score = result['anomaly_score']
            except Exception as e:
                print(f"Error analyzing log {log.id}: {e}")
                # Set default values
                log.is_anomaly = False
                log.anomaly_score = 0.0
        
        db.commit()
        offset += batch_size
