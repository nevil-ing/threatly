from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from src.core.database import get_db
from src.core.security import get_current_user
from src.services.incident_service import IncidentService
from src.schemas.incident import (
    IncidentCreate, IncidentUpdate, IncidentResponse, IncidentDetails,
    IncidentActionCreate, IncidentActionUpdate, IncidentActionResponse,
    IncidentTimelineCreate, IncidentTimelineResponse,
    IncidentStats, IncidentStatus, IncidentSeverity
)

router = APIRouter(prefix="/incidents", tags=["Incident Response"])

# ============= INCIDENT ENDPOINTS =============

@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new incident"""
    try:
        # Set created_by from current user if not provided
        if not incident_data.created_by:
            incident_data.created_by = current_user.get("sub", "unknown")
        
        incident = IncidentService.create_incident(db, incident_data)
        return incident
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create incident: {str(e)}"
        )

@router.get("/", response_model=List[IncidentResponse])
async def get_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"),
    severity: Optional[IncidentSeverity] = None,
    assigned_to: Optional[str] = None,
    incident_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get incidents with optional filters"""
    incidents = IncidentService.get_incidents(
        db=db,
        skip=skip,
        limit=limit,
        status=status_filter,
        severity=severity,
        assigned_to=assigned_to,
        incident_type=incident_type
    )
    return incidents

@router.get("/{incident_id}", response_model=IncidentDetails)
async def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get incident details with actions, timeline, and related alerts"""
    incident = IncidentService.get_incident_with_details(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Format the response with related data
    incident_details = {
        **incident.__dict__,
        "actions": incident.actions,
        "timeline": sorted(incident.timeline, key=lambda x: x.created_at),
        "related_alerts": [
            {
                "id": alert.id,
                "threat_type": alert.threat_type,
                "severity": alert.severity,
                "description": alert.description,
                "created_at": alert.created_at
            }
            for alert in incident.alerts
        ]
    }
    
    return incident_details

@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    incident_data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an incident"""
    updated_by = current_user.get("sub", "unknown")
    incident = IncidentService.update_incident(db, incident_id, incident_data, updated_by)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return incident

@router.post("/{incident_id}/close", response_model=IncidentResponse)
async def close_incident(
    incident_id: int,
    resolution_summary: str,
    root_cause: str,
    lessons_learned: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Close an incident with resolution details"""
    closed_by = current_user.get("sub", "unknown")
    incident = IncidentService.close_incident(
        db, incident_id, resolution_summary, root_cause, lessons_learned, closed_by
    )
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return incident

# ============= ACTION ENDPOINTS =============

@router.post("/{incident_id}/actions", response_model=IncidentActionResponse, status_code=status.HTTP_201_CREATED)
async def create_incident_action(
    incident_id: int,
    action_data: IncidentActionCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new action for an incident"""
    # Set created_by from current user if not provided
    if not action_data.created_by:
        action_data.created_by = current_user.get("sub", "unknown")
    
    action = IncidentService.create_action(db, incident_id, action_data)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return action

@router.get("/{incident_id}/actions", response_model=List[IncidentActionResponse])
async def get_incident_actions(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all actions for an incident"""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return incident.actions

@router.put("/actions/{action_id}", response_model=IncidentActionResponse)
async def update_incident_action(
    action_id: int,
    action_data: IncidentActionUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an incident action"""
    updated_by = current_user.get("sub", "unknown")
    action = IncidentService.update_action(db, action_id, action_data, updated_by)
    
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action not found"
        )
    
    return action

# ============= TIMELINE ENDPOINTS =============

@router.post("/{incident_id}/timeline", response_model=IncidentTimelineResponse, status_code=status.HTTP_201_CREATED)
async def add_timeline_entry(
    incident_id: int,
    timeline_data: IncidentTimelineCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Add a timeline entry to an incident"""
    # Set created_by from current user if not provided
    if not timeline_data.created_by:
        timeline_data.created_by = current_user.get("sub", "unknown")
    
    timeline_entry = IncidentService.add_timeline_entry(db, incident_id, timeline_data)
    if not timeline_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return timeline_entry

@router.get("/{incident_id}/timeline", response_model=List[IncidentTimelineResponse])
async def get_incident_timeline(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get timeline for an incident"""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Return timeline sorted by creation time
    return sorted(incident.timeline, key=lambda x: x.created_at)

# ============= STATISTICS AND DASHBOARD ENDPOINTS =============

@router.get("/stats/dashboard", response_model=IncidentStats)
async def get_incident_dashboard(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get incident statistics for dashboard"""
    stats = IncidentService.get_incident_stats(db, days)
    return stats

@router.get("/stats/summary")
async def get_incident_summary(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get high-level incident summary"""
    from sqlalchemy import func
    from src.models.incident import Incident
    
    # Quick summary stats
    total_open = db.query(Incident).filter(
        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING])
    ).count()
    
    total_critical = db.query(Incident).filter(
        Incident.severity == IncidentSeverity.CRITICAL,
        Incident.status != IncidentStatus.CLOSED
    ).count()
    
    sla_breached = db.query(Incident).filter(
        Incident.sla_breached == True,
        Incident.status != IncidentStatus.CLOSED
    ).count()
    
    return {
        "open_incidents": total_open,
        "critical_incidents": total_critical,
        "sla_breached": sla_breached,
        "requires_attention": total_critical + sla_breached
    }

# ============= UTILITY ENDPOINTS =============

@router.post("/check-sla-breaches")
async def check_sla_breaches(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Check for SLA breaches (admin only)"""
    # Add to background tasks to avoid blocking
    background_tasks.add_task(IncidentService.check_sla_breaches, db)
    return {"message": "SLA breach check initiated"}

@router.post("/alerts/{alert_id}/create-incident", response_model=IncidentResponse)
async def create_incident_from_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create an incident from an alert"""
    from src.models.alert import Alert
    
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    created_by = current_user.get("sub", "unknown")
    incident = IncidentService.auto_create_from_alert(db, alert, created_by)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot create incident from this alert (severity too low or already linked)"
        )
    
    return incident

@router.get("/types/list")
async def get_incident_types(
    current_user: dict = Depends(get_current_user)
):
    """Get list of available incident types"""
    return {
        "incident_types": [
            "Security",
            "Availability", 
            "Performance",
            "Data Breach",
            "Malware",
            "System Compromise",
            "Network Intrusion",
            "Unauthorized Access",
            "DDoS",
            "Data Loss",
            "Compliance Violation",
            "Other"
        ]
    }

@router.get("/playbooks/{incident_type}")
async def get_response_playbook(
    incident_type: str,
    severity: IncidentSeverity,
    current_user: dict = Depends(get_current_user)
):
    """Get response playbook for incident type and severity"""
    # This would typically come from a database or configuration
    playbooks = {
        "Security": {
            "CRITICAL": {
                "immediate_actions": [
                    "Activate incident response team",
                    "Isolate affected systems immediately",
                    "Preserve evidence",
                    "Notify CISO and senior management"
                ],
                "investigation_steps": [
                    "Analyze attack vectors",
                    "Identify compromised accounts/systems",
                    "Assess data exposure risk",
                    "Document timeline of events"
                ],
                "containment_actions": [
                    "Block malicious IPs/domains",
                    "Disable compromised accounts",
                    "Apply emergency patches",
                    "Implement network segmentation"
                ],
                "recovery_steps": [
                    "Rebuild compromised systems",
                    "Restore from clean backups",
                    "Update security controls",
                    "Conduct security validation"
                ],
                "communication_plan": [
                    "Internal stakeholder notification",
                    "Customer communication (if needed)",
                    "Regulatory notification (if required)",
                    "Media response preparation"
                ]
            },
            "HIGH": {
                "immediate_actions": [
                    "Alert security team",
                    "Begin initial assessment",
                    "Document initial findings"
                ],
                "investigation_steps": [
                    "Analyze security logs",
                    "Check for lateral movement",
                    "Assess impact scope"
                ],
                "containment_actions": [
                    "Apply security patches",
                    "Update firewall rules",
                    "Monitor suspicious activity"
                ],
                "recovery_steps": [
                    "Verify system integrity",
                    "Update monitoring rules",
                    "Conduct lessons learned"
                ],
                "communication_plan": [
                    "Notify security team",
                    "Update management",
                    "Document for compliance"
                ]
            }
        }
    }
    
    playbook = playbooks.get(incident_type, {}).get(severity.value, {})
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No playbook found for {incident_type} - {severity.value}"
        )
    
    return {
        "incident_type": incident_type,
        "severity": severity.value,
        "playbook": playbook
    }

# ============= BULK OPERATIONS =============

@router.post("/bulk/assign")
async def bulk_assign_incidents(
    incident_ids: List[int],
    assigned_to: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Bulk assign incidents to a user"""
    updated_by = current_user.get("sub", "unknown")
    updated_incidents = []
    
    for incident_id in incident_ids:
        incident_data = IncidentUpdate(assigned_to=assigned_to)
        incident = IncidentService.update_incident(db, incident_id, incident_data, updated_by)
        if incident:
            updated_incidents.append(incident.id)
    
    return {
        "message": f"Assigned {len(updated_incidents)} incidents to {assigned_to}",
        "updated_incidents": updated_incidents
    }

@router.post("/bulk/update-status")
async def bulk_update_status(
    incident_ids: List[int],
    status: IncidentStatus,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Bulk update incident status"""
    updated_by = current_user.get("sub", "unknown")
    updated_incidents = []
    
    for incident_id in incident_ids:
        incident_data = IncidentUpdate(status=status)
        incident = IncidentService.update_incident(db, incident_id, incident_data, updated_by)
        if incident:
            updated_incidents.append(incident.id)
    
    return {
        "message": f"Updated status for {len(updated_incidents)} incidents",
        "updated_incidents": updated_incidents,
        "new_status": status.value
    }

# ============= REPORTING ENDPOINTS =============

@router.get("/reports/monthly")
async def get_monthly_report(
    year: int = Query(..., ge=2020),
    month: int = Query(..., ge=1, le=12),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get monthly incident report"""
    from datetime import datetime, timedelta
    from calendar import monthrange
    
    # Calculate date range for the month
    start_date = datetime(year, month, 1)
    _, last_day = monthrange(year, month)
    end_date = datetime(year, month, last_day, 23, 59, 59)
    
    from src.models.incident import Incident
    
    # Get incidents for the month
    incidents = db.query(Incident).filter(
        Incident.created_at >= start_date,
        Incident.created_at <= end_date
    ).all()
    
    # Calculate metrics
    total_incidents = len(incidents)
    resolved_incidents = len([i for i in incidents if i.resolved_at])
    avg_resolution_time = 0
    
    if resolved_incidents > 0:
        total_time = sum([
            (i.resolved_at - i.created_at).total_seconds() / 3600 
            for i in incidents if i.resolved_at
        ])
        avg_resolution_time = total_time / resolved_incidents
    
    # Group by severity
    severity_breakdown = {}
    for incident in incidents:
        severity = str(incident.severity)
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
    
    # Group by type
    type_breakdown = {}
    for incident in incidents:
        incident_type = incident.incident_type
        type_breakdown[incident_type] = type_breakdown.get(incident_type, 0) + 1
    
    # SLA performance
    sla_breached = len([i for i in incidents if i.sla_breached])
    sla_performance = ((total_incidents - sla_breached) / total_incidents * 100) if total_incidents > 0 else 100
    
    return {
        "period": f"{year}-{month:02d}",
        "total_incidents": total_incidents,
        "resolved_incidents": resolved_incidents,
        "resolution_rate": (resolved_incidents / total_incidents * 100) if total_incidents > 0 else 0,
        "avg_resolution_time_hours": round(avg_resolution_time, 2),
        "sla_performance_percent": round(sla_performance, 2),
        "severity_breakdown": severity_breakdown,
        "type_breakdown": type_breakdown,
        "top_incidents": [
            {
                "id": i.id,
                "title": i.title,
                "severity": str(i.severity),
                "created_at": i.created_at,
                "resolved_at": i.resolved_at,
                "duration_hours": (
                    (i.resolved_at - i.created_at).total_seconds() / 3600 
                    if i.resolved_at else None
                )
            }
            for i in sorted(incidents, key=lambda x: x.severity.value if hasattr(x.severity, 'value') else 0, reverse=True)[:10]
        ]
    }

@router.get("/reports/export")
async def export_incidents(
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    format: str = Query("json", regex="^(json|csv)$"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Export incidents data"""
    from src.models.incident import Incident
    
    incidents = db.query(Incident).filter(
        Incident.created_at >= start_date,
        Incident.created_at <= end_date
    ).all()
    
    if format == "csv":
        import csv
        from io import StringIO
        from fastapi.responses import StreamingResponse
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "ID", "Title", "Type", "Severity", "Priority", "Status",
            "Created At", "Resolved At", "Created By", "Assigned To",
            "SLA Breached", "Business Impact"
        ])
        
        # Write data
        for incident in incidents:
            writer.writerow([
                incident.id,
                incident.title,
                incident.incident_type,
                str(incident.severity),
                incident.priority,
                str(incident.status),
                incident.created_at.isoformat() if incident.created_at else "",
                incident.resolved_at.isoformat() if incident.resolved_at else "",
                incident.created_by,
                incident.assigned_to,
                incident.sla_breached,
                incident.business_impact
            ])
        
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=incidents_export.csv"}
        )
    
    else:  # JSON format
        return {
            "export_date": datetime.utcnow().isoformat(),
            "date_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_incidents": len(incidents),
            "incidents": [
                {
                    "id": i.id,
                    "title": i.title,
                    "incident_type": i.incident_type,
                    "severity": str(i.severity),
                    "priority": i.priority,
                    "status": str(i.status),
                    "created_at": i.created_at.isoformat() if i.created_at else None,
                    "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
                    "created_by": i.created_by,
                    "assigned_to": i.assigned_to,
                    "sla_breached": i.sla_breached,
                    "business_impact": i.business_impact,
                    "resolution_summary": i.resolution_summary,
                    "root_cause": i.root_cause,
                    "lessons_learned": i.lessons_learned
                }
                for i in incidents
            ]
        }

# ============= SEARCH AND FILTERING =============

@router.get("/search")
async def search_incidents(
    q: str = Query(..., min_length=3),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Search incidents by title, description, or related data"""
    from src.models.incident import Incident
    from sqlalchemy import or_
    
    search_term = f"%{q}%"
    
    incidents = db.query(Incident).filter(
        or_(
            Incident.title.ilike(search_term),
            Incident.description.ilike(search_term),
            Incident.incident_type.ilike(search_term),
            Incident.root_cause.ilike(search_term),
            Incident.resolution_summary.ilike(search_term)
        )
    ).offset(skip).limit(limit).all()
    
    return {
        "query": q,
        "total_found": len(incidents),
        "incidents": incidents
    }

@router.get("/filters/options")
async def get_filter_options(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get available filter options for incidents"""
    from src.models.incident import Incident
    from sqlalchemy import distinct
    
    # Get unique values for filtering
    incident_types = [r[0] for r in db.query(distinct(Incident.incident_type)).all() if r[0]]
    assigned_users = [r[0] for r in db.query(distinct(Incident.assigned_to)).all() if r[0]]
    created_users = [r[0] for r in db.query(distinct(Incident.created_by)).all() if r[0]]
    
    return {
        "incident_types": incident_types,
        "severities": [s.value for s in IncidentSeverity],
        "statuses": [s.value for s in IncidentStatus],
        "priorities": ["P1", "P2", "P3", "P4"],
        "assigned_users": assigned_users,
        "created_users": created_users
    }

# ============= METRICS AND ANALYTICS =============

@router.get("/metrics/performance")
async def get_performance_metrics(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get incident response performance metrics"""
    from datetime import datetime, timedelta
    from src.models.incident import Incident
    from sqlalchemy import func
    
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Response time metrics
    incidents_with_response = db.query(Incident).filter(
        Incident.created_at >= cutoff_date,
        Incident.first_response_at.isnot(None)
    ).all()
    
    avg_response_time = 0
    if incidents_with_response:
        total_response_time = sum([
            (i.first_response_at - i.created_at).total_seconds() / 60
            for i in incidents_with_response
        ])
        avg_response_time = total_response_time / len(incidents_with_response)
    
    # Resolution time metrics
    resolved_incidents = db.query(Incident).filter(
        Incident.created_at >= cutoff_date,
        Incident.resolved_at.isnot(None)
    ).all()
    
    avg_resolution_time = 0
    if resolved_incidents:
        total_resolution_time = sum([
            (i.resolved_at - i.created_at).total_seconds() / 3600
            for i in resolved_incidents
        ])
        avg_resolution_time = total_resolution_time / len(resolved_incidents)
    
    # SLA compliance
    total_incidents = db.query(Incident).filter(Incident.created_at >= cutoff_date).count()
    sla_breached = db.query(Incident).filter(
        Incident.created_at >= cutoff_date,
        Incident.sla_breached == True
    ).count()
    
    sla_compliance = ((total_incidents - sla_breached) / total_incidents * 100) if total_incidents > 0 else 100
    
    # Trend data (daily counts for the period)
    daily_stats = []
    for i in range(days):
        day_start = cutoff_date + timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        
        day_incidents = db.query(Incident).filter(
            Incident.created_at >= day_start,
            Incident.created_at < day_end
        ).count()
        
        day_resolved = db.query(Incident).filter(
            Incident.resolved_at >= day_start,
            Incident.resolved_at < day_end
        ).count()
        
        daily_stats.append({
            "date": day_start.date().isoformat(),
            "created": day_incidents,
            "resolved": day_resolved
        })
    
    return {
        "period_days": days,
        "total_incidents": total_incidents,
        "avg_response_time_minutes": round(avg_response_time, 2),
        "avg_resolution_time_hours": round(avg_resolution_time, 2),
        "sla_compliance_percent": round(sla_compliance, 2),
        "incidents_with_response": len(incidents_with_response),
        "resolved_incidents": len(resolved_incidents),
        "daily_trend": daily_stats
    }

@router.get("/metrics/workload")
async def get_workload_metrics(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get current workload distribution"""
    from src.models.incident import Incident
    from sqlalchemy import func
    
    # Active incidents by assignee
    active_by_assignee = dict(
        db.query(Incident.assigned_to, func.count(Incident.id))
        .filter(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]))
        .filter(Incident.assigned_to.isnot(None))
        .group_by(Incident.assigned_to)
        .all()
    )
    
    # Incidents by severity (active only)
    active_by_severity = dict(
        db.query(Incident.severity, func.count(Incident.id))
        .filter(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]))
        .group_by(Incident.severity)
        .all()
    )
    
    # Overdue incidents (past SLA)
    overdue_incidents = db.query(Incident).filter(
        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
        Incident.sla_breached == True
    ).count()
    
    # High priority incidents
    high_priority = db.query(Incident).filter(
        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
        Incident.priority.in_(["P1", "P2"])
    ).count()
    
    # Unassigned incidents
    unassigned = db.query(Incident).filter(
        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
        Incident.assigned_to.is_(None)
    ).count()
    
    return {
        "active_incidents_by_assignee": active_by_assignee,
        "active_incidents_by_severity": {str(k): v for k, v in active_by_severity.items()},
        "overdue_incidents": overdue_incidents,
        "high_priority_incidents": high_priority,
        "unassigned_incidents": unassigned,
        "total_active": sum(active_by_assignee.values()) + unassigned
    }

# ============= NOTIFICATION ENDPOINTS =============

@router.post("/{incident_id}/notify")
async def send_incident_notification(
    incident_id: int,
    notification_type: str = Query(..., regex="^(escalation|update|resolution)$"),
    message: str = "",
    recipients: List[str] = [],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Send notification about incident"""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Add timeline entry for notification
    timeline_data = IncidentTimelineCreate(
        event_type="Notification",
        description=f"{notification_type.title()} notification sent: {message}",
        created_by=current_user.get("sub", "unknown"),
        metadata={
            "notification_type": notification_type,
            "recipients": recipients,
            "message": message
        }
    )
    
    IncidentService.add_timeline_entry(db, incident_id, timeline_data)
    
    # Here you would integrate with your notification service
    # For now, we'll just return success
    return {
        "message": f"Notification sent for incident {incident_id}",
        "type": notification_type,
        "recipients": recipients
    }

# ============= TEMPLATE ENDPOINTS =============

@router.get("/templates/incident-types")
async def get_incident_templates(
    current_user: dict = Depends(get_current_user)
):
    """Get incident creation templates"""
    templates = {
        "Security Breach": {
            "title": "Security Incident - [Brief Description]",
            "description": "**Initial Assessment:**\n- Threat detected: [Threat Type]\n- Affected systems: [List systems]\n- Potential impact: [Describe impact]\n\n**Immediate Actions Taken:**\n- [ ] Systems isolated\n- [ ] Evidence preserved\n- [ ] Stakeholders notified\n\n**Next Steps:**\n- [ ] Full investigation\n- [ ] Containment measures\n- [ ] Recovery planning",
            "incident_type": "Security",
            "severity": "HIGH",
            "priority": "P2",
            "business_impact": "To be assessed"
        },
        "System Outage": {
            "title": "System Outage - [System Name]",
            "description": "**Outage Details:**\n- Affected system: [System name]\n- Start time: [Time]\n- Impact: [User/business impact]\n- Root cause: [If known]\n\n**Recovery Actions:**\n- [ ] Issue identified\n- [ ] Fix implemented\n- [ ] System restored\n- [ ] Monitoring confirmed",
            "incident_type": "Availability",
            "severity": "MEDIUM",
            "priority": "P3",
            "business_impact": "Service disruption"
        },
        "Data Breach": {
            "title": "Data Breach - [Data Type]",
            "description": "**Breach Details:**\n- Data type affected: [Personal/Financial/Health/etc.]\n- Number of records: [Estimate]\n- Discovery method: [How discovered]\n- Potential exposure: [Internal/External]\n\n**Immediate Actions:**\n- [ ] Breach contained\n- [ ] Legal team notified\n- [ ] Regulatory requirements reviewed\n- [ ] Affected parties identified",
            "incident_type": "Data Breach",
            "severity": "CRITICAL",
            "priority": "P1",
            "business_impact": "Regulatory and reputational risk"
        },
        "Malware Detection": {
            "title": "Malware Incident - [Malware Type]",
            "description": "**Malware Details:**\n- Malware type: [Virus/Trojan/Ransomware/etc.]\n- Affected systems: [List systems]\n- Detection method: [AV/EDR/Manual]\n- Spread assessment: [Contained/Spreading]\n\n**Response Actions:**\n- [ ] Infected systems isolated\n- [ ] Malware analysis initiated\n- [ ] Clean-up procedures started\n- [ ] Prevention measures updated",
            "incident_type": "Security",
            "severity": "HIGH",
            "priority": "P2",
            "business_impact": "System integrity compromise"
        }
    }
    
    return {"templates": templates}

@router.get("/templates/actions/{incident_type}")
async def get_action_templates(
    incident_type: str,
    severity: IncidentSeverity,
    current_user: dict = Depends(get_current_user)
):
    """Get action templates for incident type"""
    action_templates = {
        "Security": {
            "CRITICAL": [
                {
                    "title": "Immediate Containment",
                    "description": "Isolate affected systems to prevent further compromise",
                    "action_type": "Containment",
                    "priority": "High"
                },
                {
                    "title": "Evidence Preservation",
                    "description": "Preserve logs, memory dumps, and other digital evidence",
                    "action_type": "Investigation",
                    "priority": "High"
                },
                {
                    "title": "Stakeholder Notification",
                    "description": "Notify CISO, legal team, and senior management",
                    "action_type": "Communication",
                    "priority": "High"
                },
                {
                    "title": "Threat Assessment",
                    "description": "Analyze the threat and determine attack vectors",
                    "action_type": "Investigation",
                    "priority": "Medium"
                }
            ],
            "HIGH": [
                {
                    "title": "Initial Investigation",
                    "description": "Gather initial information about the security event",
                    "action_type": "Investigation",
                    "priority": "High"
                },
                {
                    "title": "Risk Assessment",
                    "description": "Assess the potential impact and risk level",
                    "action_type": "Investigation",
                    "priority": "Medium"
                },
                {
                    "title": "Containment Planning",
                    "description": "Develop plan to contain the security incident",
                    "action_type": "Containment",
                    "priority": "Medium"
                }
            ]
        },
        "Availability": {
            "CRITICAL": [
                {
                    "title": "Service Restoration",
                    "description": "Implement immediate measures to restore service",
                    "action_type": "Recovery",
                    "priority": "High"
                },
                {
                    "title": "Root Cause Analysis",
                    "description": "Identify the root cause of the outage",
                    "action_type": "Investigation",
                    "priority": "High"
                },
                {
                    "title": "Customer Communication",
                    "description": "Notify affected customers about the outage",
                    "action_type": "Communication",
                    "priority": "Medium"
                }
            ]
        }
    }
    
    templates = action_templates.get(incident_type, {}).get(severity.value, [])
    return {"action_templates": templates}

# ============= INTEGRATION ENDPOINTS =============

@router.post("/{incident_id}/integrate/jira")
async def create_jira_ticket(
    incident_id: int,
    project_key: str,
    issue_type: str = "Bug",
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create JIRA ticket for incident (placeholder for integration)"""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Placeholder for JIRA integration
    # In real implementation, you would use JIRA API
    jira_ticket_id = f"{project_key}-{incident_id}"
    
    # Add timeline entry
    timeline_data = IncidentTimelineCreate(
        event_type="Integration",
        description=f"JIRA ticket created: {jira_ticket_id}",
        created_by=current_user.get("sub", "unknown"),
        metadata={
            "integration_type": "jira",
            "ticket_id": jira_ticket_id,
            "project_key": project_key
        }
    )
    
    IncidentService.add_timeline_entry(db, incident_id, timeline_data)
    
    return {
        "message": "JIRA ticket created successfully",
        "ticket_id": jira_ticket_id,
        "incident_id": incident_id
    }

@router.post("/{incident_id}/integrate/slack")
async def create_slack_channel(
    incident_id: int,
    channel_name: str = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create Slack channel for incident coordination"""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Generate channel name if not provided
    if not channel_name:
        channel_name = f"incident-{incident_id}-{incident.incident_type.lower()}"
    
    # Placeholder for Slack integration
    # In real implementation, you would use Slack API
    
    # Add timeline entry
    timeline_data = IncidentTimelineCreate(
        event_type="Integration",
        description=f"Slack channel created: #{channel_name}",
        created_by=current_user.get("sub", "unknown"),
        metadata={
            "integration_type": "slack",
            "channel_name": channel_name
        }
    )
    
    IncidentService.add_timeline_entry(db, incident_id, timeline_data)
    
    return {
        "message": "Slack channel created successfully",
        "channel_name": channel_name,
        "incident_id": incident_id
    }

# ============= AUTOMATION ENDPOINTS =============

@router.post("/{incident_id}/automate/containment")
async def trigger_automated_containment(
    incident_id: int,
    containment_actions: List[str],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Trigger automated containment actions"""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Placeholder for automation integration
    # In real implementation, you would trigger SOAR playbooks
    
    executed_actions = []
    for action in containment_actions:
        # Simulate action execution
        executed_actions.append({
            "action": action,
            "status": "executed",
            "timestamp": datetime.utcnow().isoformat()
        })
    
    # Add timeline entry
    timeline_data = IncidentTimelineCreate(
        event_type="Automation",
        description=f"Automated containment executed: {', '.join(containment_actions)}",
        created_by=current_user.get("sub", "unknown"),
        metadata={
            "automation_type": "containment",
            "actions": executed_actions
        }
    )
    
    IncidentService.add_timeline_entry(db, incident_id, timeline_data)
    
    return {
        "message": "Automated containment triggered",
        "executed_actions": executed_actions,
        "incident_id": incident_id
    }

# ============= COMPLIANCE AND AUDIT =============

@router.get("/{incident_id}/compliance-check")
async def check_compliance_requirements(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Check compliance requirements for incident"""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    compliance_requirements = []
    
    # Check for data breach notification requirements
    if incident.incident_type == "Data Breach":
        compliance_requirements.extend([
            {
                "regulation": "GDPR",
                "requirement": "Notify supervisory authority within 72 hours",
                "deadline": (incident.created_at + timedelta(hours=72)).isoformat(),
                "status": "pending"
            },
            {
                "regulation": "GDPR",
                "requirement": "Notify data subjects if high risk",
                "deadline": "As soon as reasonably feasible",
                "status": "assessment_required"
            }
        ])
    
    # Check for security incident reporting
    if incident.incident_type == "Security" and incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
        compliance_requirements.append({
            "regulation": "SOX/SOC2",
            "requirement": "Document security incident response",
            "deadline": "Within incident resolution",
            "status": "ongoing"
        })
    
    return {
        "incident_id": incident_id,
        "compliance_requirements": compliance_requirements,
        "total_requirements": len(compliance_requirements)
    }

@router.get("/{incident_id}/audit-trail")
async def get_incident_audit_trail(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get complete audit trail for incident"""
    incident = IncidentService.get_incident_with_details(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Compile complete audit trail
    audit_events = []
    
    # Incident creation and updates
    audit_events.append({
        "timestamp": incident.created_at.isoformat(),
        "event_type": "incident_created",
        "user": incident.created_by,
        "details": f"Incident created: {incident.title}"
    })
    
    if incident.updated_at and incident.updated_at != incident.created_at:
        audit_events.append({
            "timestamp": incident.updated_at.isoformat(),
            "event_type": "incident_updated",
            "user": "system",
            "details": "Incident details updated"
        })
    
    # Timeline events
    for timeline_entry in incident.timeline:
        audit_events.append({
            "timestamp": timeline_entry.created_at.isoformat(),
            "event_type": "timeline_entry",
            "user": timeline_entry.created_by,
            "details": f"{timeline_entry.event_type}: {timeline_entry.description}"
        })
    
    # Action events
    for action in incident.actions:
        audit_events.append({
            "timestamp": action.created_at.isoformat(),
            "event_type": "action_created",
            "user": action.created_by,
            "details": f"Action created: {action.title}"
        })
        
        if action.completed_at:
            audit_events.append({
                "timestamp": action.completed_at.isoformat(),
                "event_type": "action_completed",
                "user": action.assigned_to or "unknown",
                "details": f"Action completed: {action.title}"
            })
    
    # Sort by timestamp
    audit_events.sort(key=lambda x: x["timestamp"])
    
    return {
        "incident_id": incident_id,
        "audit_trail": audit_events,
        "total_events": len(audit_events)
    }

