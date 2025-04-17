# app/services/log_service.py
from sqlalchemy.orm import Session

from src import models
from src.schemas.log import Log, LogCreate, LogUpdate 

def create_log(db: Session, log: LogCreate):
    db_log = models.Log(**log.dict()) # Create SQLAlchemy model instance from Pydantic model
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def get_logs(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Log).offset(skip).limit(limit).all()

def get_log(db: Session, log_id: int):
    return db.query(models.Log).filter(models.Log.id == log_id).first()

def update_log(db: Session, log_id: int, log: LogUpdate):
    db_log = get_log(db, log_id=log_id)
    if not db_log:
        return None
    for key, value in log.dict(exclude_unset=True).items(): # Iterate over only set values in Pydantic model
        setattr(db_log, key, value) # Update SQLAlchemy model attributes
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def delete_log(db: Session, log_id: int):
    db_log = get_log(db, log_id=log_id)
    if not db_log:
        return None
    db.delete(db_log)
    db.commit()
    return db_log