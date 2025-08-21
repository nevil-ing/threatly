from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models import Log
from src.schemas import LogCreate, LogUpdate
from src.services import storage_service
import logging
import json

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/logs/")
async def create_log(log: LogCreate, request: Request, db: Session = Depends(get_db)):
    """Create a new log entry and queue it for anomaly detection"""
    try:
        # Store the log in the database
        db_log = storage_service.store_log(db=db, log_data=log)
        if not db_log:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store log entry in the database."
            )
        
        # Queue the log for anomaly detection
        logger.info(f"Queuing log {db_log.id} for anomaly detection")
        job = await request.app.state.redis.enqueue_job(
            'detect_anomaly_task',
            db_log.data,  # Pass the log data
            db_log.id     # Pass the log ID
        )
        
        logger.info(f"Log {db_log.id} queued successfully with job ID: {job.job_id}")
        
        return {
            "status": "Log received and scheduled for analysis", 
            "log_id": db_log.id,
            "job_id": job.job_id
        }
    
    except Exception as e:
        logger.error(f"Error creating log: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create log: {str(e)}"
        )

@router.get("/logs/", tags=["logs"])
async def read_all_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all logs with pagination"""
    db_logs = db.query(Log).offset(skip).limit(limit).all()
    total_count = db.query(Log).count()
    
    return {
        "logs": db_logs,
        "total": total_count,
        "skip": skip,
        "limit": limit
    }

@router.get("/logs/{log_id}")
async def read_log(log_id: int, db: Session = Depends(get_db)):
    """Get a specific log by ID"""
    db_log = db.query(Log).filter(Log.id == log_id).first()
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return db_log

@router.put("/logs/{log_id}")
async def update_log(log_id: int, log: LogUpdate, db: Session = Depends(get_db)):
    """Update a specific log"""
    db_log = db.query(Log).filter(Log.id == log_id).first()
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Update fields
    if log.source_type is not None:
        db_log.source_type = log.source_type
    if log.source_ip is not None:
        db_log.source_ip = log.source_ip
    if log.data is not None:
        db_log.data = log.data
    if log.is_anomaly is not None:
        db_log.is_anomaly = log.is_anomaly
    if log.anomaly_score is not None:
        db_log.anomaly_score = log.anomaly_score
    
    db.commit()
    db.refresh(db_log)
    return {"status": "Log updated successfully", "log_id": db_log.id}

@router.get("/anomalies/", tags=["anomalies"])
async def get_anomalies(
    threshold: float = 0.5, 
    limit: int = 100, 
    skip: int = 0,
    db: Session = Depends(get_db)
):
    """Get logs that are marked as anomalies or have an anomaly score above threshold"""
    db_logs = db.query(Log).filter(
        (Log.is_anomaly == True) | (Log.anomaly_score >= threshold)
    ).order_by(Log.timestamp.desc()).offset(skip).limit(limit).all()
    
    total_anomalies = db.query(Log).filter(
        (Log.is_anomaly == True) | (Log.anomaly_score >= threshold)
    ).count()
    
    return {
        "anomalies": db_logs,
        "total": total_anomalies,
        "threshold": threshold,
        "skip": skip,
        "limit": limit
    }

@router.post("/analyze-existing/", tags=["anomalies"])
async def analyze_existing_logs(
    request: Request,
    threshold: float = 0.5, 
    db: Session = Depends(get_db)
):
    """Analyze existing logs that haven't been evaluated for anomalies yet"""
    try:
        # Check how many logs need analysis
        unscored_count = db.query(Log).filter(Log.anomaly_score.is_(None)).count()
        
        if unscored_count == 0:
            return {"status": "No logs need analysis", "unscored_logs": 0}
        
        # Queue the batch analysis job
        job = await request.app.state.redis.enqueue_job(
            'analyze_logs_batch_task', 
            threshold
        )
        
        logger.info(f"Batch analysis queued with job ID: {job.job_id} for {unscored_count} logs")
        
        return {
            "status": "Background analysis started",
            "job_id": job.job_id,
            "unscored_logs": unscored_count,
            "threshold": threshold
        }
    
    except Exception as e:
        logger.error(f"Error starting batch analysis: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start batch analysis: {str(e)}"
        )

@router.get("/analysis-status/", tags=["anomalies"])
async def get_analysis_status(db: Session = Depends(get_db)):
    """Get the current status of log analysis"""
    total_logs = db.query(Log).count()
    analyzed_logs = db.query(Log).filter(Log.anomaly_score.is_not(None)).count()
    anomalous_logs = db.query(Log).filter(Log.is_anomaly == True).count()
    unscored_logs = total_logs - analyzed_logs
    
    return {
        "total_logs": total_logs,
        "analyzed_logs": analyzed_logs,
        "unscored_logs": unscored_logs,
        "anomalous_logs": anomalous_logs,
        "analysis_progress": f"{analyzed_logs}/{total_logs}" if total_logs > 0 else "0/0"
    }