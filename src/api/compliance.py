# src/routers/compliance.py
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from src.core.database import get_db
from src.models.compliance import ComplianceReport
from src.schemas.compliance import ComplianceReportCreate, ComplianceReportResponse

router = APIRouter(prefix="/compliance", tags=["Compliance"])

@router.post("/", response_model=ComplianceReportResponse, status_code=202) # 202 Accepted
async def create_compliance_report(
    report_data: ComplianceReportCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Accepts a request to generate a compliance report for an alert.
    
    This endpoint immediately returns a 'Pending' report and queues the
    heavy analysis (LLM inference) to be run in the background.
    """
    # Create the initial report record in the database with "Pending" status
    db_report = ComplianceReport(
        alert_id=report_data.alert_id,
        framework=report_data.framework
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    
    # Add the long-running analysis task to the background worker queue
    # This assumes you have an ARQ worker set up.
    # background_tasks.add_task(run_compliance_analysis_task, db_report.id)
    
    # For ARQ, you would enqueue the job like this:
    # from arq.connections import create_pool
    # redis = await create_pool()
    # await redis.enqueue_job('run_compliance_analysis_task', db_report.id)
    
    return db_report

@router.get("/{report_id}", response_model=ComplianceReportResponse)
async def get_compliance_report(report_id: int, db: Session = Depends(get_db)):
    """
    Retrieves the status and results of a compliance report.
    """
    db_report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Report not found")
    return db_report

@router.get("/", response_model=List[ComplianceReportResponse])
async def get_all_compliance_reports(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieves a list of all compliance reports.
    """
    reports = db.query(ComplianceReport).offset(skip).limit(limit).all()
    return reports