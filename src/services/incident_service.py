from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import logging

from src.models.incident import Incident, IncidentAction, IncidentTimeline, IncidentStatus, IncidentSeverity
from src.models.alert import Alert
from src.schemas.incident import (
    IncidentCreate, IncidentUpdate, IncidentActionCreate, 
    IncidentActionUpdate, IncidentTimelineCreate
)

logger = logging.getLogger(__name__)

class IncidentService:
    
    @staticmethod
    def create_incident(db: Session, incident_data: IncidentCreate) -> Incident:
        """Create a new incident"""
        try:
            # Create incident
            db_incident = Incident(
                title=incident_data.title,
                description=incident_data.description,
                incident_type=incident_data.incident_type,
                severity=incident_data.severity,
                priority=incident_data.priority,
                created_by=incident_data.created_by,
                assigned_to=incident_data.assigned_to,
                affected_systems=incident_data.affected_systems,
                business_impact=incident_data.business_impact,
                estimated_cost=incident_data.estimated_cost,
                response_sla_minutes=IncidentService._get_response_sla(incident_data.priority),
                resolution_sla_hours=IncidentService._get_resolution_sla(incident_data.priority)
            )
            
            db.add(db_incident)
            db.flush()  # Get the ID
            
            # Link related alerts
            if incident_data.alert_ids:
                alerts = db.query(Alert).filter(Alert.id.in_(incident_data.alert_ids)).all()
                db_incident.alerts.extend(alerts)
            
            # Create initial timeline entry
            timeline_entry = IncidentTimeline(
                incident_id=db_incident.id,
                event_type="Created",
                description=f"Incident created: {incident_data.title}",
                created_by=incident_data.created_by
            )
            db.add(timeline_entry)
            
            # Generate initial response actions
            initial_actions = IncidentService._generate_initial_actions(
                incident_data.incident_type, 
                incident_data.severity,
                incident_data.created_by
            )
            
            for action_data in initial_actions:
                action = IncidentAction(
                    incident_id=db_incident.id,
                    **action_data
                )
                db.add(action)
            
            db.commit()
            db.refresh(db_incident)
            
            logger.info(f"Incident {db_incident.id} created successfully")
            return db_incident
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create incident: {str(e)}")
            raise
    
    @staticmethod
    def get_incident(db: Session, incident_id: int) -> Optional[Incident]:
        """Get incident by ID"""
        return db.query(Incident).filter(Incident.id == incident_id).first()
    
    @staticmethod
    def get_incidents(
        db: Session, 
        skip: int = 0, 
        limit: int = 100,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        assigned_to: Optional[str] = None,
        incident_type: Optional[str] = None
    ) -> List[Incident]:
        """Get incidents with optional filters"""
        query = db.query(Incident)
        
        if status:
            query = query.filter(Incident.status == status)
        if severity:
            query = query.filter(Incident.severity == severity)
        if assigned_to:
            query = query.filter(Incident.assigned_to == assigned_to)
        if incident_type:
            query = query.filter(Incident.incident_type == incident_type)
        
        return query.order_by(desc(Incident.created_at)).offset(skip).limit(limit).all()
    
    @staticmethod
    def update_incident(db: Session, incident_id: int, incident_data: IncidentUpdate, updated_by: str) -> Optional[Incident]:
        """Update an incident"""
        try:
            db_incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if not db_incident:
                return None
            
            # Track changes for timeline
            changes = []
            
            # Update fields
            update_data = incident_data.dict(exclude_unset=True)
            for field, value in update_data.items():
                if hasattr(db_incident, field):
                    old_value = getattr(db_incident, field)
                    if old_value != value:
                        changes.append(f"{field}: {old_value} → {value}")
                        setattr(db_incident, field, value)
            
            # Handle status changes
            if incident_data.status and db_incident.status != incident_data.status:
                IncidentService._handle_status_change(db_incident, incident_data.status, updated_by)
            
            db_incident.updated_at = datetime.utcnow()
            
            # Add timeline entry for changes
            if changes:
                timeline_entry = IncidentTimeline(
                    incident_id=incident_id,
                    event_type="Updated",
                    description=f"Incident updated: {', '.join(changes)}",
                    created_by=updated_by
                )
                db.add(timeline_entry)
            
            db.commit()
            db.refresh(db_incident)
            
            logger.info(f"Incident {incident_id} updated successfully")
            return db_incident
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to update incident {incident_id}: {str(e)}")
            raise
    
    @staticmethod
    def create_action(db: Session, incident_id: int, action_data: IncidentActionCreate) -> Optional[IncidentAction]:
        """Create a new action for an incident"""
        try:
            # Verify incident exists
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if not incident:
                return None
            
            db_action = IncidentAction(
                incident_id=incident_id,
                action_type=action_data.action_type,
                title=action_data.title,
                description=action_data.description,
                assigned_to=action_data.assigned_to,
                created_by=action_data.created_by,
                priority=action_data.priority,
                due_date=action_data.due_date
            )
            
            db.add(db_action)
            
            # Add timeline entry
            timeline_entry = IncidentTimeline(
                incident_id=incident_id,
                event_type="Action Created",
                description=f"New action created: {action_data.title}",
                created_by=action_data.created_by
            )
            db.add(timeline_entry)
            
            db.commit()
            db.refresh(db_action)
            
            logger.info(f"Action {db_action.id} created for incident {incident_id}")
            return db_action
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create action for incident {incident_id}: {str(e)}")
            raise
    
    @staticmethod
    def update_action(db: Session, action_id: int, action_data: IncidentActionUpdate, updated_by: str) -> Optional[IncidentAction]:
        """Update an incident action"""
        try:
            db_action = db.query(IncidentAction).filter(IncidentAction.id == action_id).first()
            if not db_action:
                return None
            
            # Track changes
            changes = []
            update_data = action_data.dict(exclude_unset=True)
            
            for field, value in update_data.items():
                if hasattr(db_action, field):
                    old_value = getattr(db_action, field)
                    if old_value != value:
                        changes.append(f"{field}: {old_value} → {value}")
                        setattr(db_action, field, value)
            
            # Handle completion
            if action_data.status == "Completed" and not db_action.completed_at:
                db_action.completed_at = datetime.utcnow()
                changes.append("Status: Completed")
            
            # Add timeline entry
            if changes:
                timeline_entry = IncidentTimeline(
                    incident_id=db_action.incident_id,
                    event_type="Action Updated",
                    description=f"Action '{db_action.title}' updated: {', '.join(changes)}",
                    created_by=updated_by
                )
                db.add(timeline_entry)
            
            db.commit()
            db.refresh(db_action)
            
            logger.info(f"Action {action_id} updated successfully")
            return db_action
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to update action {action_id}: {str(e)}")
            raise
    
    @staticmethod
    def add_timeline_entry(db: Session, incident_id: int, timeline_data: IncidentTimelineCreate) -> Optional[IncidentTimeline]:
        """Add a timeline entry to an incident"""
        try:
            # Verify incident exists
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if not incident:
                return None
            
            db_timeline = IncidentTimeline(
                incident_id=incident_id,
                event_type=timeline_data.event_type,
                description=timeline_data.description,
                created_by=timeline_data.created_by,
                metadata=timeline_data.metadata
            )
            
            db.add(db_timeline)
            db.commit()
            db.refresh(db_timeline)
            
            return db_timeline
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to add timeline entry for incident {incident_id}: {str(e)}")
            raise
    
    @staticmethod
    def get_incident_stats(db: Session, days: int = 30) -> Dict[str, Any]:
        """Get incident statistics"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Basic counts
            total_incidents = db.query(Incident).filter(Incident.created_at >= cutoff_date).count()
            open_incidents = db.query(Incident).filter(
                and_(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]), 
                     Incident.created_at >= cutoff_date)
            ).count()
            critical_incidents = db.query(Incident).filter(
                and_(Incident.severity == IncidentSeverity.CRITICAL, 
                     Incident.created_at >= cutoff_date)
            ).count()
            
            # Average resolution time
            resolved_incidents = db.query(Incident).filter(
                and_(Incident.resolved_at.isnot(None), 
                     Incident.created_at >= cutoff_date)
            ).all()
            
            avg_resolution_time = 0
            if resolved_incidents:
                total_time = sum([
                    (incident.resolved_at - incident.created_at).total_seconds() / 3600 
                    for incident in resolved_incidents
                ])
                avg_resolution_time = total_time / len(resolved_incidents)
            
            # SLA breach rate
            sla_breached = db.query(Incident).filter(
                and_(Incident.sla_breached == True, 
                     Incident.created_at >= cutoff_date)
            ).count()
            sla_breach_rate = (sla_breached / total_incidents * 100) if total_incidents > 0 else 0
            
            # Incidents by type
            incidents_by_type = dict(
                db.query(Incident.incident_type, func.count(Incident.id))
                .filter(Incident.created_at >= cutoff_date)
                .group_by(Incident.incident_type)
                .all()
            )
            
            # Incidents by severity
            incidents_by_severity = dict(
                db.query(Incident.severity, func.count(Incident.id))
                .filter(Incident.created_at >= cutoff_date)
                .group_by(Incident.severity)
                .all()
            )
            
            # Recent incidents
            recent_incidents = db.query(Incident).filter(
                Incident.created_at >= cutoff_date
            ).order_by(desc(Incident.created_at)).limit(10).all()
            
            return {
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "critical_incidents": critical_incidents,
                "avg_resolution_time_hours": round(avg_resolution_time, 2),
                "sla_breach_rate": round(sla_breach_rate, 2),
                "incidents_by_type": incidents_by_type,
                "incidents_by_severity": {str(k): v for k, v in incidents_by_severity.items()},
                "recent_incidents": recent_incidents
            }
            
        except Exception as e:
            logger.error(f"Failed to get incident stats: {str(e)}")
            raise
    
    @staticmethod
    def auto_create_from_alert(db: Session, alert: Alert, created_by: str = "system") -> Optional[Incident]:
        """Automatically create incident from high-severity alert"""
        try:
            # Only auto-create for high/critical severity threats
            if alert.severity not in ["High", "Critical"]:
                return None
            
            # Check if alert is already linked to an incident
            existing_incident = db.query(Incident).join(Incident.alerts).filter(Alert.id == alert.id).first()
            if existing_incident:
                return existing_incident
            
            # Determine incident details based on alert
            incident_type = IncidentService._map_threat_to_incident_type(alert.threat_type)
            severity = IncidentSeverity.HIGH if alert.severity == "High" else IncidentSeverity.CRITICAL
            priority = "P1" if alert.severity == "Critical" else "P2"
            
            incident_data = IncidentCreate(
                title=f"Security Incident: {alert.threat_type} - {alert.source_ip or 'Unknown IP'}",
                description=f"Automatically created incident from alert {alert.id}.\n\n"
                           f"Threat Type: {alert.threat_type}\n"
                           f"Severity: {alert.severity}\n"
                           f"Description: {alert.description}\n"
                           f"Source IP: {alert.source_ip or 'Unknown'}\n"
                           f"Source Type: {alert.source_type or 'Unknown'}",
                incident_type=incident_type,
                severity=severity,
                priority=priority,
                created_by=created_by,
                affected_systems=alert.source_type,
                business_impact="To be assessed",
                alert_ids=[alert.id]
            )
            
            incident = IncidentService.create_incident(db, incident_data)
            logger.info(f"Auto-created incident {incident.id} from alert {alert.id}")
            return incident
            
        except Exception as e:
            logger.error(f"Failed to auto-create incident from alert {alert.id}: {str(e)}")
            return None
    
    @staticmethod
    def _get_response_sla(priority: str) -> int:
        """Get response SLA in minutes based on priority"""
        sla_mapping = {
            "P1": 15,   # 15 minutes for critical
            "P2": 60,   # 1 hour for high
            "P3": 240,  # 4 hours for medium
            "P4": 1440  # 24 hours for low
        }
        return sla_mapping.get(priority, 240)
    
    @staticmethod
    def _get_resolution_sla(priority: str) -> int:
        """Get resolution SLA in hours based on priority"""
        sla_mapping = {
            "P1": 4,    # 4 hours for critical
            "P2": 24,   # 24 hours for high
            "P3": 72,   # 72 hours for medium
            "P4": 168   # 1 week for low
        }
        return sla_mapping.get(priority, 72)
    
    @staticmethod
    def _map_threat_to_incident_type(threat_type: str) -> str:
        """Map threat type to incident type"""
        mapping = {
            "SQL Injection": "Security",
            "XSS Attack": "Security",
            "Command Injection": "Security",
            "Path Traversal": "Security",
            "Brute Force": "Security",
            "DDoS": "Availability",
            "Malware": "Security",
            "Data Exfiltration": "Data Breach",
            "Authentication Bypass": "Security",
            "Privilege Escalation": "Security",
            "CSRF": "Security",
            "XXE": "Security",
            "LDAP Injection": "Security",
            "File Upload Attack": "Security",
            "Suspicious Activity": "Security",
            "Unknown Anomaly": "Security"
        }
        return mapping.get(threat_type, "Security")
    
    @staticmethod
    def _handle_status_change(incident: Incident, new_status: IncidentStatus, updated_by: str):
        """Handle incident status changes and update timestamps"""
        now = datetime.utcnow()
        
        if new_status == IncidentStatus.INVESTIGATING and not incident.first_response_at:
            incident.first_response_at = now
        elif new_status == IncidentStatus.RESOLVED and not incident.resolved_at:
            incident.resolved_at = now
        elif new_status == IncidentStatus.CLOSED and not incident.closed_at:
            incident.closed_at = now
        
        # Check for SLA breaches
        if incident.first_response_at and incident.response_sla_minutes:
            response_time_minutes = (incident.first_response_at - incident.created_at).total_seconds() / 60
            if response_time_minutes > incident.response_sla_minutes:
                incident.sla_breached = True
        
        if incident.resolved_at and incident.resolution_sla_hours:
            resolution_time_hours = (incident.resolved_at - incident.created_at).total_seconds() / 3600
            if resolution_time_hours > incident.resolution_sla_hours:
                incident.sla_breached = True
    
    @staticmethod
    def _generate_initial_actions(incident_type: str, severity: IncidentSeverity, created_by: str) -> List[Dict[str, Any]]:
        """Generate initial response actions based on incident type and severity"""
        actions = []
        
        # Common actions for all security incidents
        if incident_type == "Security":
            actions.extend([
                {
                    "action_type": "Investigation",
                    "title": "Initial Threat Assessment",
                    "description": "Analyze the threat indicators and determine the scope of the incident",
                    "priority": "High",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(hours=1)
                },
                {
                    "action_type": "Containment",
                    "title": "Isolate Affected Systems",
                    "description": "Identify and isolate systems that may be compromised",
                    "priority": "High",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(hours=2)
                },
                {
                    "action_type": "Communication",
                    "title": "Notify Security Team",
                    "description": "Alert the security team and relevant stakeholders",
                    "priority": "Medium",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(minutes=30)
                }
            ])
        
        # Critical severity additional actions
        if severity == IncidentSeverity.CRITICAL:
            actions.extend([
                {
                    "action_type": "Escalation",
                    "title": "Escalate to Management",
                    "description": "Notify senior management and prepare executive briefing",
                    "priority": "High",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(minutes=15)
                },
                {
                    "action_type": "Communication",
                    "title": "Prepare External Communications",
                    "description": "Draft customer/public communications if needed",
                    "priority": "Medium",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(hours=4)
                }
            ])
        
        # Specific actions based on incident type
        if incident_type == "Data Breach":
            actions.extend([
                {
                    "action_type": "Investigation",
                    "title": "Data Impact Assessment",
                    "description": "Determine what data may have been accessed or exfiltrated",
                    "priority": "High",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(hours=2)
                },
                {
                    "action_type": "Compliance",
                    "title": "Review Regulatory Requirements",
                    "description": "Check if incident requires regulatory notification (GDPR, HIPAA, etc.)",
                    "priority": "High",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(hours=4)
                }
            ])
        
        elif incident_type == "Availability":
            actions.extend([
                {
                    "action_type": "Recovery",
                    "title": "Restore Service Availability",
                    "description": "Implement measures to restore normal service operations",
                    "priority": "High",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(hours=1)
                },
                {
                    "action_type": "Monitoring",
                    "title": "Enhanced Monitoring",
                    "description": "Implement additional monitoring to detect similar attacks",
                    "priority": "Medium",
                    "created_by": created_by,
                    "due_date": datetime.utcnow() + timedelta(hours=6)
                }
            ])
        
        return actions
    
    @staticmethod
    def check_sla_breaches(db: Session) -> List[Incident]:
        """Check for SLA breaches and update incidents"""
        try:
            now = datetime.utcnow()
            breached_incidents = []
            
            # Check response SLA breaches
            response_breaches = db.query(Incident).filter(
                and_(
                    Incident.first_response_at.is_(None),
                    Incident.status == IncidentStatus.OPEN,
                    Incident.sla_breached == False
                )
            ).all()
            
            for incident in response_breaches:
                if incident.response_sla_minutes:
                    elapsed_minutes = (now - incident.created_at).total_seconds() / 60
                    if elapsed_minutes > incident.response_sla_minutes:
                        incident.sla_breached = True
                        breached_incidents.append(incident)
                        
                        # Add timeline entry
                        timeline_entry = IncidentTimeline(
                            incident_id=incident.id,
                            event_type="SLA Breach",
                            description=f"Response SLA breached - {elapsed_minutes:.0f} minutes elapsed",
                            created_by="system"
                        )
                        db.add(timeline_entry)
            
            # Check resolution SLA breaches
            resolution_breaches = db.query(Incident).filter(
                and_(
                    Incident.resolved_at.is_(None),
                    Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]),
                    Incident.sla_breached == False
                )
            ).all()
            
            for incident in resolution_breaches:
                if incident.resolution_sla_hours:
                    elapsed_hours = (now - incident.created_at).total_seconds() / 3600
                    if elapsed_hours > incident.resolution_sla_hours:
                        incident.sla_breached = True
                        breached_incidents.append(incident)
                        
                        # Add timeline entry
                        timeline_entry = IncidentTimeline(
                            incident_id=incident.id,
                            event_type="SLA Breach",
                            description=f"Resolution SLA breached - {elapsed_hours:.1f} hours elapsed",
                            created_by="system"
                        )
                        db.add(timeline_entry)
            
            if breached_incidents:
                db.commit()
                logger.warning(f"Found {len(breached_incidents)} SLA breaches")
            
            return breached_incidents
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to check SLA breaches: {str(e)}")
            return []
    
    @staticmethod
    def get_incident_with_details(db: Session, incident_id: int) -> Optional[Incident]:
        """Get incident with all related data (actions, timeline, alerts)"""
        return db.query(Incident).filter(Incident.id == incident_id).first()
    
    @staticmethod
    def close_incident(db: Session, incident_id: int, resolution_summary: str, root_cause: str, lessons_learned: str, closed_by: str) -> Optional[Incident]:
        """Close an incident with resolution details"""
        try:
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if not incident:
                return None
            
            # Update incident
            incident.status = IncidentStatus.CLOSED
            incident.closed_at = datetime.utcnow()
            incident.resolution_summary = resolution_summary
            incident.root_cause = root_cause
            incident.lessons_learned = lessons_learned
            incident.updated_at = datetime.utcnow()
            
            # Add timeline entry
            timeline_entry = IncidentTimeline(
                incident_id=incident_id,
                event_type="Closed",
                description=f"Incident closed by {closed_by}",
                created_by=closed_by,
                metadata=json.dumps({
                    "resolution_summary": resolution_summary,
                    "root_cause": root_cause,
                    "lessons_learned": lessons_learned
                })
            )
            db.add(timeline_entry)
            
            db.commit()
            db.refresh(incident)
            
            logger.info(f"Incident {incident_id} closed successfully")
            return incident
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to close incident {incident_id}: {str(e)}")
            raise
