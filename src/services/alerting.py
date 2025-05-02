# app/services/alerting.py
import logging
from sqlalchemy.orm import Session

from src import models, schemas 
from src.core.config import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def trigger_alert(log_entry: models.Log, db: Session):
    """
    Triggers an alert based on an anomalous log entry.
    """
    alert_description = f"Anomaly detected in log ID {log_entry.id}. Source: {log_entry.source_type}, IP: {log_entry.source_ip}, Score: {log_entry.anomaly_score:.2f}"
    score = log_entry.anomaly_score
    for i in range(score):
        if score <= 3:
            alert_severity = "Low"
        elif score >= 4 and score <= 6:
            alert_severity = "Medium"
        else:
            alert_severity = "High"        
    
  #
    logging.warning(f"ALERT TRIGGERED: {alert_description}")

    # --- Step 1: Store Alert in Database---
    try:
        alert_data = schemas.AlertCreate(
            log_id=log_entry.id,
            severity=alert_severity,
            description=alert_description
        )
        db_alert = models.Alert(**alert_data.dict())
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)
        logging.info(f"Alert {db_alert.id} stored in database for log {log_entry.id}")
    except Exception as e:
        logging.error(f"Failed to store alert in database: {e}")
        db.rollback() # Rollback if storing alert fails

    # --- send alert notifications---
    # 
    # if settings.ALERTING_EMAIL_TO:
    #     send_email_alert(subject=f"Sentinel XDR Alert: {alert_severity}",
    #                      body=alert_description,
    #                      recipient=settings.ALERTING_EMAIL_TO)

    # Example: Send to Slack
    # send_slack_notification(channel="#security-alerts", message=alert_description)

# --- Placeholder functions for other alert mechanisms ---
# def send_email_alert(subject: str, body: str, recipient: str):
#     logging.info(f"Simulating sending email alert to {recipient}: Subject='{subject}'")
#     # Add actual email sending logic using smtplib or a library like 'emails'
