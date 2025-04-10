
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.schemas.log import Log, LogCreate, LogUpdate 
from app.services.log_service import create_log, delete_log, update_log, get_log, get_logs
from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User

router = APIRouter() 
#add logs
"""
@router.post("/logs/", response_model=Log, status_code=201) # Use Log schema for response, 201 Created
def create_new_log(log: LogCreate, db: Session = Depends(get_db)):
    
    return create_log(db=db, log=log) # log_service
    
"""

#get logs[list]
@router.get("/logs/", response_model=List[Log])
def read_logs_list(
    skip: int = 0,
    limit: int = 100, 
    db: Session = Depends(get_db),
    current_user: User= Depends(get_current_active_user)
    ):
    """
    Retrieve a list of logs.
    """
    logs = get_logs(db, skip=skip, limit=limit)
    return logs
#get log
@router.get("/logs/{log_id}", response_model=Log)
def read_log(
    log_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
    ):
    """
    Retrieve a specific log by ID.
    """
    db_log = get_log(db, log_id=log_id)
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return db_log
#update logs
@router.put("/logs/{log_id}", response_model=Log)
def update_log(
    log_id: int, 
    log: LogUpdate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
    ):
    """
    Update a log entry by ID.
    """
    db_log = get_log(db, log_id=log_id)
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return update_log(db=db, log_id=log_id, log=log)
#delete logs
@router.delete("/logs/{log_id}", response_model=Log)
def delete_log(
    log_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
    ):
    """
    Delete a log entry by ID.
    """
    db_log = get_log(db, log_id=log_id)
    if db_log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return delete_log(db=db, log_id=log_id)