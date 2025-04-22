from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models import Log  
from src.schemas import LogCreate, LogUpdate 



router = APIRouter()


@router.post("/logs/")
async def create_log(log: LogCreate, db: Session = Depends(get_db)):
    db_log = Log(
        timestamp=log.timestamp,
        source_type=log.source_type,
        source_ip=log.source_ip,
        data=log.data,
        is_anomaly=log.is_anomaly,
        anomaly_score=log.anomaly_score
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return {"status": "Log received successfully!", "log_id": db_log.id}

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
