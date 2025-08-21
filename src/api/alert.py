from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, func
from src.core.database import get_db
from src.models.alert import Alert
from src.models.log import Log
from src.schemas.alert import AlertResponse, AlertUpdate, PaginatedAlertResponse
from typing import List, Optional
from datetime import datetime, timedelta

router = APIRouter()

@router.get("/alerts/", response_model=PaginatedAlertResponse, tags=["Alert"])
async def get_alerts(
    skip: int = 0,
    limit: int = 100,
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low)"),
    alert_status: Optional[str] = Query(None, description="Filter by status (Open, Investigating, Resolved, False Positive)"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    days: Optional[int] = Query(None, description="Filter by days back"),
    db: Session = Depends(get_db)):
    
    """Get all alerts with optional filters and threat type information"""
    
    query = db.query(Alert).join(Log, Alert.log_id == Log.id)
    
    # Apply filters
    if threat_type:
        query = query.filter(Alert.threat_type == threat_type)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if alert_status:
        query = query.filter(Alert.status == alert_status)
    
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    
    if days:
        start_date = datetime.now() - timedelta(days=days)
        query = query.filter(Alert.created_at >= start_date)
    
    # Get total count before applying pagination
    total_count = query.count()
    
    # Order by creation date (newest first) and apply pagination
    query = query.order_by(desc(Alert.created_at))
    db_alerts = query.offset(skip).limit(limit).all()
    
    # Convert SQLAlchemy objects to Pydantic models explicitly
    alert_responses = [AlertResponse.model_validate(alert) for alert in db_alerts]
    
    # Return structured response with pagination metadata
    return PaginatedAlertResponse(
        alerts=alert_responses,
        total=total_count,
        skip=skip,
        limit=limit
    )
    
@router.get("/alerts/{alert_id}", response_model=AlertResponse, tags=["Alert"])
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get a specific alert with full threat type details"""
    
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not db_alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    
    # Explicitly convert to Pydantic model
    return AlertResponse.model_validate(db_alert)

@router.get("/alerts/threat-types/{threat_type}", response_model=List[AlertResponse], tags=["Alert"])
async def get_alerts_by_threat_type(
    threat_type: str,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    alert_status: Optional[str] = Query(None, description="Filter by status"),
    days: Optional[int] = Query(7, description="Days to look back"),
    db: Session = Depends(get_db)
):
    """Get all alerts for a specific threat type"""
    
    query = db.query(Alert).filter(Alert.threat_type == threat_type)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if alert_status:
        query = query.filter(Alert.status == alert_status)
    
    if days:
        start_date = datetime.now() - timedelta(days=days)
        query = query.filter(Alert.created_at >= start_date)
    
    query = query.order_by(desc(Alert.created_at))
    db_alerts = query.offset(skip).limit(limit).all()
    
    if not db_alerts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"No alerts found for threat type: {threat_type}"
        )
    
    # Convert SQLAlchemy objects to Pydantic models
    return [AlertResponse.model_validate(alert) for alert in db_alerts]

@router.put("/alerts/{alert_id}/status", response_model=AlertResponse, tags=["Alert"])
async def update_alert_status(
    alert_id: int,
    alert_update: AlertUpdate,
    db: Session = Depends(get_db)
):
    """Update alert status, assignment, and resolution notes"""
    
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not db_alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    
    # Update fields if provided
    if alert_update.status:
        db_alert.status = alert_update.status
    
    if alert_update.assigned_to:
        db_alert.assigned_to = alert_update.assigned_to
    
    if alert_update.resolution_notes:
        db_alert.resolution_notes = alert_update.resolution_notes
    
    db_alert.updated_at = datetime.now()
    
    try:
        db.commit()
        db.refresh(db_alert)
        # Explicitly convert to Pydantic model
        return AlertResponse.model_validate(db_alert)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Failed to update alert: {str(e)}"
        )

@router.get("/alerts/dashboard/stats", tags=["Alert"])
async def get_alert_dashboard_stats(
    days: int = Query(7, description="Number of days for dashboard data"),
    db: Session = Depends(get_db)
):
    """Get comprehensive dashboard statistics for alerts"""
    
    start_date = datetime.now() - timedelta(days=days)
    
    # Basic counts
    total_alerts = db.query(Alert).filter(Alert.created_at >= start_date).count()
    critical_alerts = db.query(Alert).filter(
        and_(Alert.created_at >= start_date, Alert.severity == "Critical")
    ).count()
    high_alerts = db.query(Alert).filter(
        and_(Alert.created_at >= start_date, Alert.severity == "High")
    ).count()
    open_alerts = db.query(Alert).filter(
        and_(Alert.created_at >= start_date, Alert.status == "Open")
    ).count()
    
    # Top threat types
    top_threats = db.query(
        Alert.threat_type,
        func.count(Alert.id).label('count'),
        func.max(Alert.severity).label('max_severity')
    ).filter(
        Alert.created_at >= start_date
    ).group_by(Alert.threat_type).order_by(desc('count')).limit(10).all()
    
    # Recent critical/high alerts
    recent_high_priority = db.query(Alert).filter(
        and_(
            Alert.created_at >= start_date,
            Alert.severity.in_(["Critical", "High"]),
            Alert.status == "Open"
        )
    ).order_by(desc(Alert.created_at)).limit(5).all()
    
    # Alerts trend by day
    daily_alerts = db.query(
        func.date(Alert.created_at).label('date'),
        func.count(Alert.id).label('count')
    ).filter(
        Alert.created_at >= start_date
    ).group_by(func.date(Alert.created_at)).order_by('date').all()
    
    # Source IP analysis
    top_source_ips = db.query(
        Alert.source_ip,
        func.count(Alert.id).label('count')
    ).filter(
        and_(Alert.created_at >= start_date, Alert.source_ip.isnot(None))
    ).group_by(Alert.source_ip).order_by(desc('count')).limit(5).all()
    
    return {
        "summary": {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "open_alerts": open_alerts,
            "resolution_rate": ((total_alerts - open_alerts) / total_alerts * 100) if total_alerts > 0 else 0
        },
        "top_threat_types": [
            {
                "threat_type": item.threat_type,
                "count": item.count,
                "max_severity": item.max_severity
            } for item in top_threats
        ],
        "recent_high_priority": [
            {
                "id": alert.id,
                "threat_type": alert.threat_type,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "created_at": alert.created_at.isoformat(),
                "description": alert.description[:100] + "..." if len(alert.description) > 100 else alert.description
            } for alert in recent_high_priority
        ],
        "daily_trend": [
            {"date": item.date.isoformat(), "count": item.count}
            for item in daily_alerts
        ],
        "top_source_ips": [
            {"source_ip": item.source_ip, "count": item.count}
            for item in top_source_ips
        ],
        "period_days": days,
        "generated_at": datetime.now().isoformat()
    }

@router.get("/alerts/threat-types/list", tags=["Alert"])
async def get_available_threat_types(db: Session = Depends(get_db)):
    """Get list of all available threat types in the system"""
    
    threat_types = db.query(Alert.threat_type).distinct().all()
    
    return {
        "threat_types": [item.threat_type for item in threat_types if item.threat_type],
        "count": len(threat_types)
    }
