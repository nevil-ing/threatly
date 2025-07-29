from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models.compliance import ComplianceReport
from src.schemas.compliance import ComplianceReportCreate, ComplianceReportRead
from src.services.compliance import analyze_compliance

router = APIRouter(prefix="/compliance", tags=["Compliance"])

@router.post("/", response_model=ComplianceReportRead)
def run_compliance(report: ComplianceReportCreate, db: Session = Depends(get_db)):
    summary, is_violation = analyze_compliance(report.input_data, report.compliance_type)
    
    report_db = ComplianceReport(
        log_id=report.log_id,
        alert_id=report.alert_id,
        compliance_type=report.compliance_type,
        input_data=report.input_data,
        result_summary=summary,
        is_violation=is_violation
    )

    db.add(report_db)
    db.commit()
    db.refresh(report_db)
    return report_db
