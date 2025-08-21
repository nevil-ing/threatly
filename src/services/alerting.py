import json
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from src.models.alert import Alert
from src.models.log import Log
from src.schemas.alert import AlertCreate
from typing import Dict, Any
from src.services.incident_service import IncidentService 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def trigger_alert(log_entry: Log, threat_classification: Dict[str, Any], db: Session) -> Alert:
    """
    Create an enhanced alert with threat type information.
    
    Args:
        log_entry: The log entry that triggered the alert
        threat_classification: Threat classification results from pattern classifier
        db: Database session
        
    Returns:
        Created Alert object
    """
    
    threat_type = threat_classification.get("threat_type", "Unknown")
    severity = threat_classification.get("severity", "Low")
    confidence = threat_classification.get("confidence", 0.0)
    matched_patterns = threat_classification.get("matched_patterns", [])
    details = threat_classification.get("details", "No additional details")
    
    # Create comprehensive alert description
    alert_description = (
        f"Security Alert: {threat_type} detected\n"
        f"Log ID: {log_entry.id}\n"
        f"Source: {log_entry.source_type or 'Unknown'}\n"
        f"IP Address: {log_entry.source_ip or 'Unknown'}\n"
        f"Confidence: {confidence:.2f}\n"
        f"Anomaly Score: {log_entry.anomaly_score:.2f}\n"
        f"Detection Time: {datetime.utcnow().isoformat()}\n"
        f"Details: {details}\n"
        f"Matched Patterns: {len(matched_patterns)} pattern(s) detected"
    )
    
    logging.warning(f"SECURITY ALERT TRIGGERED: {threat_type} - Severity: {severity} - IP: {log_entry.source_ip}")
    
    try:
        # Create alert record
        db_alert = Alert(
            log_id=log_entry.id,
            threat_type=threat_type,
            severity=severity,
            description=alert_description,
            confidence_score=str(confidence),
            matched_patterns=json.dumps(matched_patterns) if matched_patterns else None,
            source_ip=log_entry.source_ip,
            source_type=log_entry.source_type,
            status="Open"
        )
        
        db.add(db_alert)
        db.flush() 
        
        logging.info(f"Alert {db_alert.id} created successfully for {threat_type} threat")
        logging.info(f"Alert Details - ID: {db_alert.id}, Severity: {severity}, Source IP: {log_entry.source_ip}")
        
        logging.info(f"Attempting to promote alert {db_alert.id} to an incident...")
        IncidentService.auto_create_from_alert(db, db_alert, created_by="system")
        # Log additional details for high severity alerts
        if severity in ["Critical", "High"]:
            logging.critical(f"HIGH SEVERITY ALERT: {threat_type} - Alert ID: {db_alert.id} - Immediate attention required!")
        
        return db_alert
        
    except Exception as e:
        logging.error(f"Failed to create alert for log {log_entry.id}: {str(e)}")
        db.rollback()
        raise Exception(f"Alert creation failed: {str(e)}")

def get_alert_statistics(db: Session, days: int = 7) -> Dict[str, Any]:
    """
    Get comprehensive alert statistics for the specified period.
    
    Args:
        db: Database session
        days: Number of days to look back
        
    Returns:
        Dictionary containing alert statistics
    """
    from datetime import timedelta
    from sqlalchemy import func, and_
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    try:
        # Basic counts
        total_alerts = db.query(Alert).filter(Alert.created_at >= start_date).count()
        open_alerts = db.query(Alert).filter(
            and_(Alert.created_at >= start_date, Alert.status == "Open")
        ).count()
        resolved_alerts = db.query(Alert).filter(
            and_(Alert.created_at >= start_date, Alert.status == "Resolved")
        ).count()
        
        # Severity breakdown
        severity_stats = db.query(
            Alert.severity,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.created_at >= start_date
        ).group_by(Alert.severity).all()
        
        # Threat type breakdown
        threat_type_stats = db.query(
            Alert.threat_type,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.created_at >= start_date
        ).group_by(Alert.threat_type).all()
        
        # Top source IPs
        top_source_ips = db.query(
            Alert.source_ip,
            func.count(Alert.id).label('count')
        ).filter(
            and_(Alert.created_at >= start_date, Alert.source_ip.isnot(None))
        ).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(10).all()
        
        return {
            "period_days": days,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "resolved_alerts": resolved_alerts,
            "resolution_rate": (resolved_alerts / total_alerts * 100) if total_alerts > 0 else 0,
            "severity_breakdown": {item.severity: item.count for item in severity_stats},
            "threat_type_breakdown": {item.threat_type: item.count for item in threat_type_stats},
            "top_source_ips": [{"ip": item.source_ip, "count": item.count} for item in top_source_ips],
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Failed to generate alert statistics: {str(e)}")
        return {
            "error": f"Failed to generate statistics: {str(e)}",
            "generated_at": datetime.utcnow().isoformat()
        }

def update_alert_status(alert_id: int, status: str, assigned_to: str = None, resolution_notes: str = None, db: Session = None) -> Alert:
    """
    Update alert status and related information.
    
    Args:
        alert_id: ID of the alert to update
        status: New status (Open, Investigating, Resolved, False Positive)
        assigned_to: Person assigned to handle the alert
        resolution_notes: Notes about the resolution
        db: Database session
        
    Returns:
        Updated Alert object
    """
    
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        
        if not alert:
            raise Exception(f"Alert with ID {alert_id} not found")
        
        # Update fields
        old_status = alert.status
        alert.status = status
        alert.updated_at = datetime.utcnow()
        
        if assigned_to:
            alert.assigned_to = assigned_to
        
        if resolution_notes:
            alert.resolution_notes = resolution_notes
        
        db.commit()
        db.refresh(alert)
        
        logging.info(f"Alert {alert_id} status updated from '{old_status}' to '{status}'")
        
        if assigned_to:
            logging.info(f"Alert {alert_id} assigned to {assigned_to}")
        
        return alert
        
    except Exception as e:
        logging.error(f"Failed to update alert {alert_id}: {str(e)}")
        db.rollback()
        raise Exception(f"Alert update failed: {str(e)}")

def get_alerts_by_threat_type(threat_type: str, db: Session, limit: int = 50) -> list:
    """
    Get alerts filtered by specific threat type.
    
    Args:
        threat_type: Type of threat to filter by
        db: Database session
        limit: Maximum number of alerts to return
        
    Returns:
        List of Alert objects
    """
    
    try:
        alerts = db.query(Alert).filter(
            Alert.threat_type == threat_type
        ).order_by(Alert.created_at.desc()).limit(limit).all()
        
        logging.info(f"Retrieved {len(alerts)} alerts for threat type: {threat_type}")
        return alerts
        
    except Exception as e:
        logging.error(f"Failed to retrieve alerts for threat type {threat_type}: {str(e)}")
        return []

def get_high_priority_alerts(db: Session, limit: int = 20) -> list:
    """
    Get high priority (Critical and High severity) open alerts.
    
    Args:
        db: Database session
        limit: Maximum number of alerts to return
        
    Returns:
        List of high priority Alert objects
    """
    
    try:
        alerts = db.query(Alert).filter(
            and_(
                Alert.severity.in_(["Critical", "High"]),
                Alert.status == "Open"
            )
        ).order_by(Alert.created_at.desc()).limit(limit).all()
        
        logging.info(f"Retrieved {len(alerts)} high priority open alerts")
        return alerts
        
    except Exception as e:
        logging.error(f"Failed to retrieve high priority alerts: {str(e)}")
        return []

# Alert severity mapping for consistent handling
ALERT_SEVERITY_LEVELS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}

def get_alert_severity_level(severity: str) -> int:
    """Get numeric level for alert severity for comparison purposes."""
    return ALERT_SEVERITY_LEVELS.get(severity, 0)
