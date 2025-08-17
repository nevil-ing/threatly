# src/api/compliance.py
import os
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc, func
from arq.connections import create_pool

from src.core.database import get_db
from src.models.compliance import ComplianceReport, ReportStatus
from src.models.alert import Alert
from src.schemas.compliance import ComplianceReportCreate, ComplianceReportResponse
from src.services.compliance_service import test_compliance_analysis, get_model_status

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["Compliance"])

# Supported compliance frameworks
SUPPORTED_FRAMEWORKS = [
    "GDPR", "HIPAA", "PCI-DSS", "SOX", "NIST", "ISO27001", 
    "CCPA", "SOC2", "FISMA", "COBIT"
]

@router.post("/reports", response_model=ComplianceReportResponse, status_code=202)
async def create_compliance_report(
    report_data: ComplianceReportCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Create a new compliance report for an alert.
    
    This endpoint immediately returns a 'Pending' report and queues the
    analysis to be run in the background by ARQ worker.
    """
    # Validate framework
    if report_data.framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported framework. Supported: {', '.join(SUPPORTED_FRAMEWORKS)}"
        )
    
    # Check if alert exists
    alert = db.query(Alert).filter(Alert.id == report_data.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Check if report already exists for this alert and framework
    existing_report = db.query(ComplianceReport).filter(
        and_(
            ComplianceReport.alert_id == report_data.alert_id,
            ComplianceReport.framework == report_data.framework
        )
    ).first()
    
    if existing_report:
        if existing_report.status in [ReportStatus.PENDING, ReportStatus.PROCESSING]:
            return existing_report
        elif existing_report.status == ReportStatus.COMPLETED:
            raise HTTPException(
                status_code=409, 
                detail="Report already exists and is completed"
            )
    
    # Create the initial report record
    db_report = ComplianceReport(
        alert_id=report_data.alert_id,
        framework=report_data.framework,
        status=ReportStatus.PENDING
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    
    # Enqueue the analysis task with ARQ
    try:
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        redis = await create_pool(redis_url)
        await redis.enqueue_job(
            'compliance_analysis_arq_task',
            db_report.id,
            _job_timeout=300  # 5 minutes timeout
        )
        logger.info(f"Enqueued compliance analysis for report {db_report.id}")
        await redis.close()
    except Exception as e:
        logger.error(f"Failed to enqueue compliance analysis: {e}")
        # Update report status to failed
        db_report.status = ReportStatus.FAILED
        db_report.summary = f"Failed to enqueue analysis: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to start analysis")
    
    return db_report

@router.get("/reports/{report_id}", response_model=ComplianceReportResponse)
async def get_compliance_report(report_id: int, db: Session = Depends(get_db)):
    """Get a specific compliance report by ID."""
    db_report = db.query(ComplianceReport).options(
        joinedload(ComplianceReport.alert)
    ).filter(ComplianceReport.id == report_id).first()
    
    if not db_report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return db_report

@router.get("/reports", response_model=List[ComplianceReportResponse])
async def get_compliance_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    framework: Optional[str] = Query(None, description="Filter by framework"),
    status: Optional[ReportStatus] = Query(None, description="Filter by status"),
    alert_id: Optional[int] = Query(None, description="Filter by alert ID"),
    is_violation: Optional[bool] = Query(None, description="Filter by violation status"),
    db: Session = Depends(get_db)
):
    """Get compliance reports with filtering options."""
    query = db.query(ComplianceReport).options(joinedload(ComplianceReport.alert))
    
    # Apply filters
    if framework:
        if framework not in SUPPORTED_FRAMEWORKS:
            raise HTTPException(status_code=400, detail="Invalid framework")
        query = query.filter(ComplianceReport.framework == framework)
    
    if status:
        query = query.filter(ComplianceReport.status == status)
    
    if alert_id:
        query = query.filter(ComplianceReport.alert_id == alert_id)
    
    if is_violation is not None:
        query = query.filter(ComplianceReport.is_violation == is_violation)
    
    # Order by creation date (newest first)
    query = query.order_by(desc(ComplianceReport.created_at))
    
    reports = query.offset(skip).limit(limit).all()
    return reports

@router.delete("/reports/{report_id}")
async def delete_compliance_report(report_id: int, db: Session = Depends(get_db)):
    """Delete a compliance report."""
    db_report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    
    if not db_report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if db_report.status == ReportStatus.PROCESSING:
        raise HTTPException(
            status_code=409, 
            detail="Cannot delete report that is currently being processed"
        )
    
    db.delete(db_report)
    db.commit()
    
    return {"message": "Report deleted successfully"}

@router.post("/reports/{report_id}/retry", response_model=ComplianceReportResponse)
async def retry_compliance_report(report_id: int, db: Session = Depends(get_db)):
    """Retry a failed compliance report."""
    db_report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    
    if not db_report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if db_report.status not in [ReportStatus.FAILED]:
        raise HTTPException(
            status_code=409, 
            detail="Can only retry failed reports"
        )
    
    # Reset report status
    db_report.status = ReportStatus.PENDING
    db_report.summary = None
    db_report.violation_details = None
    db_report.recommended_actions = None
    db_report.is_violation = None
    db_report.completed_at = None
    db.commit()
    
    # Enqueue the analysis task again
    try:
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        redis = await create_pool(redis_url)
        await redis.enqueue_job(
            'compliance_analysis_arq_task',
            db_report.id,
            _job_timeout=300
        )
        logger.info(f"Re-enqueued compliance analysis for report {db_report.id}")
        await redis.close()
    except Exception as e:
        logger.error(f"Failed to re-enqueue compliance analysis: {e}")
        db_report.status = ReportStatus.FAILED
        db_report.summary = f"Failed to re-enqueue analysis: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to retry analysis")
    
    return db_report

@router.get("/reports/alert/{alert_id}", response_model=List[ComplianceReportResponse])
async def get_reports_by_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get all compliance reports for a specific alert."""
    # Check if alert exists
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    reports = db.query(ComplianceReport).filter(
        ComplianceReport.alert_id == alert_id
    ).order_by(desc(ComplianceReport.created_at)).all()
    
    return reports

@router.get("/frameworks")
async def get_supported_frameworks():
    """Get list of supported compliance frameworks."""
    return {
        "frameworks": SUPPORTED_FRAMEWORKS,
        "descriptions": {
            "GDPR": "General Data Protection Regulation - EU data protection",
            "HIPAA": "Health Insurance Portability and Accountability Act - US healthcare",
            "PCI-DSS": "Payment Card Industry Data Security Standard",
            "SOX": "Sarbanes-Oxley Act - US financial reporting",
            "NIST": "NIST Cybersecurity Framework",
            "ISO27001": "ISO/IEC 27001 - Information security management",
            "CCPA": "California Consumer Privacy Act",
            "SOC2": "Service Organization Control 2",
            "FISMA": "Federal Information Security Management Act",
            "COBIT": "Control Objectives for Information and Related Technologies"
        }
    }

@router.get("/dashboard/stats")
async def get_compliance_dashboard_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    db: Session = Depends(get_db)
):
    """Get compliance dashboard statistics."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Total reports
    total_reports = db.query(ComplianceReport).filter(
        ComplianceReport.created_at >= cutoff_date
    ).count()
    
    # Reports by status
    status_counts = db.query(
        ComplianceReport.status,
        func.count(ComplianceReport.id)
    ).filter(
        ComplianceReport.created_at >= cutoff_date
    ).group_by(ComplianceReport.status).all()
    
    # Violation statistics
    violation_stats = db.query(
        ComplianceReport.is_violation,
        func.count(ComplianceReport.id)
    ).filter(
        and_(
            ComplianceReport.created_at >= cutoff_date,
            ComplianceReport.status == ReportStatus.COMPLETED
        )
    ).group_by(ComplianceReport.is_violation).all()
    
    # Framework breakdown
    framework_counts = db.query(
        ComplianceReport.framework,
        func.count(ComplianceReport.id)
    ).filter(
        ComplianceReport.created_at >= cutoff_date
    ).group_by(ComplianceReport.framework).all()
    
    # Recent violations
    recent_violations = db.query(ComplianceReport).options(
        joinedload(ComplianceReport.alert)
    ).filter(
        and_(
            ComplianceReport.created_at >= cutoff_date,
            ComplianceReport.is_violation == True,
            ComplianceReport.status == ReportStatus.COMPLETED
        )
    ).order_by(desc(ComplianceReport.created_at)).limit(10).all()
    
    return {
        "period_days": days,
        "total_reports": total_reports,
        "status_breakdown": {status.value: count for status, count in status_counts},
        "violation_stats": {
            "violations": next((count for violation, count in violation_stats if violation), 0),
            "compliant": next((count for violation, count in violation_stats if not violation), 0)
        },
        "framework_breakdown": {framework: count for framework, count in framework_counts},
        "recent_violations": [
            {
                "report_id": report.id,
                "framework": report.framework,
                "alert_id": report.alert_id,
                "threat_type": report.alert.threat_type if report.alert else None,
                "severity": report.alert.severity if report.alert else None,
                "created_at": report.created_at
            }
            for report in recent_violations
        ]
    }

@router.post("/test/{alert_id}")
async def test_compliance_analysis_endpoint(
    alert_id: int,
    framework: str = Query(..., description="Framework to test"),
    db: Session = Depends(get_db)
):
    """Test compliance analysis for an alert without creating a report."""
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported framework. Supported: {', '.join(SUPPORTED_FRAMEWORKS)}"
        )
    
    try:
        result = test_compliance_analysis(alert_id, framework, db)
        return {
            "alert_id": alert_id,
            "framework": framework,
            "test_result": result,
            "timestamp": datetime.utcnow()
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Test compliance analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Analysis test failed")

@router.get("/model/status")
async def get_compliance_model_status():
    """Get the status of the compliance analysis model."""
    try:
        status = get_model_status()
        return status
    except Exception as e:
        logger.error(f"Failed to get model status: {e}")
        return {"error": str(e), "status": "error"}

@router.post("/bulk-analyze")
async def bulk_compliance_analysis(
    alert_ids: List[int],
    frameworks: List[str],
    db: Session = Depends(get_db)
):
    """Create compliance reports for multiple alerts and frameworks."""
    # Validate frameworks
    invalid_frameworks = [f for f in frameworks if f not in SUPPORTED_FRAMEWORKS]
    if invalid_frameworks:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid frameworks: {', '.join(invalid_frameworks)}"
        )
    
    # Validate alerts exist
    existing_alerts = db.query(Alert.id).filter(Alert.id.in_(alert_ids)).all()
    existing_alert_ids = [alert.id for alert in existing_alerts]
    missing_alerts = [aid for aid in alert_ids if aid not in existing_alert_ids]
    
    if missing_alerts:
        raise HTTPException(
            status_code=404,
            detail=f"Alerts not found: {', '.join(map(str, missing_alerts))}"
        )
    
    created_reports = []
    skipped_reports = []
    failed_reports = []
    
    try:
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        redis = await create_pool(redis_url)
        
        for alert_id in alert_ids:
            for framework in frameworks:
                # Check if report already exists
                existing_report = db.query(ComplianceReport).filter(
                    and_(
                        ComplianceReport.alert_id == alert_id,
                        ComplianceReport.framework == framework
                    )
                ).first()
                
                if existing_report:
                    skipped_reports.append({
                        "alert_id": alert_id,
                        "framework": framework,
                        "reason": f"Report already exists with status: {existing_report.status.value}"
                    })
                    continue
                
                # Create new report
                try:
                    db_report = ComplianceReport(
                        alert_id=alert_id,
                        framework=framework,
                        status=ReportStatus.PENDING
                    )
                    db.add(db_report)
                    db.commit()
                    db.refresh(db_report)
                    
                    # Enqueue analysis
                    await redis.enqueue_job(
                        'compliance_analysis_arq_task',
                        db_report.id,
                        _job_timeout=300
                    )
                    
                    created_reports.append({
                        "report_id": db_report.id,
                        "alert_id": alert_id,
                        "framework": framework
                    })
                    
                except Exception as e:
                    failed_reports.append({
                        "alert_id": alert_id,
                        "framework": framework,
                        "error": str(e)
                    })
        
        await redis.close()
        
    except Exception as e:
        logger.error(f"Bulk analysis setup failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup bulk analysis")
    
    return {
        "created": len(created_reports),
        "skipped": len(skipped_reports),
        "failed": len(failed_reports),
        "details": {
            "created_reports": created_reports,
            "skipped_reports": skipped_reports,
            "failed_reports": failed_reports
        }
    }

@router.get("/reports/{report_id}/pdf")
async def download_compliance_report_pdf(report_id: int, db: Session = Depends(get_db)):
    """Download a compliance report as PDF."""
    from src.services.compliance_service import generate_compliance_report_pdf
    
    db_report = db.query(ComplianceReport).options(
        joinedload(ComplianceReport.alert)
    ).filter(ComplianceReport.id == report_id).first()
    
    if not db_report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if db_report.status != ReportStatus.COMPLETED:
        raise HTTPException(
            status_code=409, 
            detail="Report is not completed yet"
        )
    
    try:
        pdf_content = generate_compliance_report_pdf(db_report)
        
        def generate():
            yield pdf_content
        
        filename = f"compliance_report_{db_report.framework}_{db_report.id}.pdf"
        
        return StreamingResponse(
            generate(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF")

@router.get("/summary/{framework}")
async def get_compliance_summary(
    framework: str,
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    db: Session = Depends(get_db)
):
    """Get a compliance summary report for a specific framework."""
    from src.services.compliance_service import generate_compliance_summary_report
    
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported framework. Supported: {', '.join(SUPPORTED_FRAMEWORKS)}"
        )
    
    try:
        summary = generate_compliance_summary_report(framework, days, db)
        return summary
    except Exception as e:
        logger.error(f"Summary generation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate summary")

@router.get("/export/csv")
async def export_compliance_reports_csv(
    framework: Optional[str] = Query(None, description="Filter by framework"),
    days: int = Query(30, ge=1, le=365, description="Number of days to export"),
    db: Session = Depends(get_db)
):
    """Export compliance reports as CSV."""
    import csv
    from io import StringIO
    
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    query = db.query(ComplianceReport).options(
        joinedload(ComplianceReport.alert)
    ).filter(ComplianceReport.created_at >= cutoff_date)
    
    if framework:
        if framework not in SUPPORTED_FRAMEWORKS:
            raise HTTPException(status_code=400, detail="Invalid framework")
        query = query.filter(ComplianceReport.framework == framework)
    
    reports = query.order_by(desc(ComplianceReport.created_at)).all()
    
    # Create CSV content
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Report ID', 'Framework', 'Alert ID', 'Status', 'Is Violation',
        'Threat Type', 'Severity', 'Source IP', 'Created At', 'Completed At',
        'Summary', 'Violation Details', 'Recommended Actions'
    ])
    
    # Write data
    for report in reports:
        writer.writerow([
            report.id,
            report.framework,
            report.alert_id,
            report.status.value,
            'Yes' if report.is_violation else 'No' if report.is_violation is not None else 'N/A',
            report.alert.threat_type if report.alert else 'N/A',
            report.alert.severity if report.alert else 'N/A',
            report.alert.source_ip if report.alert else 'N/A',
            report.created_at.isoformat(),
            report.completed_at.isoformat() if report.completed_at else 'N/A',
            report.summary or 'N/A',
            report.violation_details or 'N/A',
            report.recommended_actions or 'N/A'
        ])
    
    output.seek(0)
    csv_content = output.getvalue()
    output.close()
    
    def generate():
        yield csv_content.encode('utf-8')
    
    filename = f"compliance_reports_{framework or 'all'}_{days}days.csv"
    
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )