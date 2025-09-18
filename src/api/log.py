from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models import Log
from src.schemas import LogCreate, LogUpdate
from src.services import storage_service
from src.services.qdrant_service import QdrantAnomalyService  # Import our new service
import logging
import json

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize Qdrant service
qdrant_service = QdrantAnomalyService()

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
    """Update a specific log and sync with Qdrant if it's an anomaly"""
    db_log = db.query(Log).filter(Log.id == log_id).first()
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Track if anomaly status changed
    was_anomaly = db_log.is_anomaly
    
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
    
    # Handle Qdrant synchronization
    try:
        if db_log.is_anomaly and not was_anomaly:
            # Newly flagged as anomaly - add to Qdrant
            success = qdrant_service.store_anomaly(
                log_id=db_log.id,
                log_data=db_log.data,
                anomaly_score=db_log.anomaly_score or 0.0,
                source_ip=db_log.source_ip,
                source_type=db_log.source_type,
                timestamp=db_log.timestamp
            )
            if not success:
                logger.warning(f"Failed to store anomaly {db_log.id} in Qdrant")
        elif not db_log.is_anomaly and was_anomaly:
            # No longer an anomaly - remove from Qdrant
            success = qdrant_service.delete_anomaly(db_log.id)
            if not success:
                logger.warning(f"Failed to remove anomaly {db_log.id} from Qdrant")
        elif db_log.is_anomaly:
            # Still an anomaly but data might have changed - update in Qdrant
            success = qdrant_service.store_anomaly(
                log_id=db_log.id,
                log_data=db_log.data,
                anomaly_score=db_log.anomaly_score or 0.0,
                source_ip=db_log.source_ip,
                source_type=db_log.source_type,
                timestamp=db_log.timestamp
            )
            if not success:
                logger.warning(f"Failed to update anomaly {db_log.id} in Qdrant")
                
    except Exception as e:
        logger.error(f"Error syncing anomaly {db_log.id} with Qdrant: {e}")
    
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
    
    # Get Qdrant statistics
    try:
        qdrant_stats = qdrant_service.get_collection_stats()
    except Exception as e:
        logger.error(f"Error getting Qdrant stats: {e}")
        qdrant_stats = {"error": str(e)}
    
    return {
        "total_logs": total_logs,
        "analyzed_logs": analyzed_logs,
        "unscored_logs": unscored_logs,
        "anomalous_logs": anomalous_logs,
        "analysis_progress": f"{analyzed_logs}/{total_logs}" if total_logs > 0 else "0/0",
        "vector_db_stats": qdrant_stats
    }

# New endpoints for vector database operations
@router.post("/anomalies/sync-to-vector/", tags=["anomalies"])
async def sync_anomalies_to_vector_db(db: Session = Depends(get_db)):
    """Sync all existing anomalies to Qdrant vector database"""
    try:
        # Get all anomalies from database
        anomalies = db.query(Log).filter(Log.is_anomaly == True).all()
        
        if not anomalies:
            return {"status": "No anomalies found to sync", "synced_count": 0}
        
        synced_count = 0
        failed_count = 0
        
        for anomaly in anomalies:
            try:
                success = qdrant_service.store_anomaly(
                    log_id=anomaly.id,
                    log_data=anomaly.data,
                    anomaly_score=anomaly.anomaly_score or 0.0,
                    source_ip=anomaly.source_ip,
                    source_type=anomaly.source_type,
                    timestamp=anomaly.timestamp
                )
                
                if success:
                    synced_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                logger.error(f"Error syncing anomaly {anomaly.id}: {e}")
                failed_count += 1
        
        return {
            "status": "Sync completed",
            "total_anomalies": len(anomalies),
            "synced_count": synced_count,
            "failed_count": failed_count
        }
        
    except Exception as e:
        logger.error(f"Error syncing anomalies to vector DB: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync anomalies: {str(e)}"
        )

@router.post("/anomalies/search-similar/", tags=["anomalies"])
async def search_similar_anomalies(
    query: str,
    limit: int = 10,
    score_threshold: float = 0.7
):
    """Search for similar anomalies using vector similarity"""
    try:
        results = qdrant_service.search_similar_anomalies(
            query_text=query,
            limit=limit,
            score_threshold=score_threshold
        )
        
        return {
            "query": query,
            "results": results,
            "count": len(results),
            "score_threshold": score_threshold
        }
        
    except Exception as e:
        logger.error(f"Error searching similar anomalies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to search similar anomalies: {str(e)}"
        )

@router.get("/anomalies/vector/{log_id}", tags=["anomalies"])
async def get_anomaly_from_vector_db(log_id: int):
    """Get anomaly details from vector database"""
    try:
        result = qdrant_service.get_anomaly_by_log_id(log_id)
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Anomaly not found in vector database"
            )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting anomaly from vector DB: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get anomaly from vector database: {str(e)}"
        )