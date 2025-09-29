# src/worker.py
import os
import requests
import logging
from arq import cron
from arq.connections import RedisSettings
from sqlalchemy.orm import Session
from src.core.database import get_db, SessionLocal
from src.models import Log, Alert
from src.models import compliance 
from src.services.compliance_service import run_compliance_analysis_task
from src.services.alerting import trigger_alert
from src.services.threat_classifier import ThreatPatternClassifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

threat_classifier = ThreatPatternClassifier()
http_session = requests.Session()
MODEL_API_URL = os.getenv("MODEL_API_URL")

if not MODEL_API_URL:
    logger.error("MODEL_API_URL environment variable is not set!")
    raise ValueError("MODEL_API_URL is required for anomaly detection")

# ARQ Task Definitions

async def detect_anomaly_task(ctx, log_data: dict, log_id: int):
    """
    ARQ task to analyze a single log entry in real-time.
    This function should execute immediately when a log is received.
    """
    start_time = ctx.get('job_start_time') if hasattr(ctx, 'get') else None
    logger.info(f"Starting anomaly detection for log ID: {log_id}")
    
    db = next(get_db())
    try:
        log_entry = db.query(Log).filter(Log.id == log_id).first()
        if not log_entry:
            logger.error(f"Log ID {log_id} not found for analysis!")
            return {"status": "error", "message": "Log not found"}
        
        # Extracting log message for analysis
        log_message = ""
        if isinstance(log_data, dict):
            
            for key in ['message', 'data', 'log_message', 'content', 'text']:
                if key in log_data:
                    if isinstance(log_data[key], dict):
                        if 'message' in log_data[key]:
                            log_message = str(log_data[key]['message'])
                        else:
                            log_message = str(log_data[key])
                    else:
                        log_message = str(log_data[key])
                    break
            
            # If no specific key found, convert whole dict to string
            if not log_message:
                log_message = str(log_data)
        else:
            log_message = str(log_data)
        
        if not log_message or log_message.strip() == '':
            logger.warning(f"⚠️ Empty log message for log ID {log_id}, marking as normal")
            log_entry.anomaly_score = 0.0
            log_entry.is_anomaly = False
            log_entry.threat_type = "Normal"
            db.commit()
            return {"status": "completed", "anomaly_score": 0.0, "is_anomaly": False}
        
        logger.info(f" Analyzing message: {log_message[:100]}{'...' if len(log_message) > 100 else ''}")
        
        # Call model API  analysis
        try:
            logger.info(f"Calling model API for REAL-TIME analysis of log ID {log_id}")
            
            # Use shorter timeout for real-time processing
            response = http_session.post(
                MODEL_API_URL, 
                json={"log_message": log_message}, 
                timeout=5  
            )
            response.raise_for_status()
            result = response.json()
            anomaly_score = result.get('anomaly_score', 0.0)
            
            logger.info(f"Log ID {log_id}: anomaly_score = {anomaly_score}")

            # Update log entry with anomaly score
            log_entry.anomaly_score = anomaly_score
            
            if anomaly_score > 0.5:  # Anomaly detected
                logger.warning(f"THREAT DETECTED! Log ID {log_id} with score {anomaly_score}")
                log_entry.is_anomaly = True
                
                
                threat_info = threat_classifier.classify_threat(
                    log_message=log_message, 
                    anomaly_score=anomaly_score,
                    source_ip=getattr(log_entry, 'source_ip', None),
                    source_type=getattr(log_entry, 'source_type', None)
                )
                log_entry.threat_type = threat_info.get("threat_type", "Unknown")
                
                db.commit()
                db.refresh(log_entry)
                
                # Trigger an alert immediately for real-time response
                try:
                    alert = trigger_alert(log_entry=log_entry, threat_classification=threat_info, db=db)
                    logger.critical(f"ALERT TRIGGERED: Alert {alert.id} for anomalous log ID: {log_id}")
                    db.commit()
            
                    logger.critical(f"TRANSACTION COMMITTED. Alert {alert.id} created for anomalous log ID: {log_id}")
                    return {
                        "status": "threat_detected",
                        "log_id": log_id,
                        "anomaly_score": anomaly_score,
                        "threat_type": threat_info.get("threat_type"),
                        "alert_id": alert.id,
                        "is_anomaly": True
                    }
                except Exception as alert_error:
                    logger.error(f"Failed to trigger alert for log {log_id}: {alert_error}")
                    return {
                        "status": "threat_detected_no_alert",
                        "log_id": log_id,
                        "anomaly_score": anomaly_score,
                        "is_anomaly": True
                    }
            else:
                logger.info(f"No threat detected for log ID {log_id}")
                log_entry.is_anomaly = False
                log_entry.threat_type = "Normal"
                db.commit()
                
                return {
                    "status": "normal",
                    "log_id": log_id,
                    "anomaly_score": anomaly_score,
                    "is_anomaly": False
                }

        except requests.exceptions.Timeout:
            logger.error(f"TIMEOUT: Model API call timed out for log {log_id}")
            
            log_entry.anomaly_score = 0.0
            log_entry.is_anomaly = False
            log_entry.threat_type = "API_Timeout"
            db.commit()
            return {"status": "timeout", "log_id": log_id}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API ERROR: Failed to call model API for log {log_id}: {e}")
           
            log_entry.anomaly_score = 0.0
            log_entry.is_anomaly = False
            log_entry.threat_type = "API_Error"
            db.commit()
            return {"status": "api_error", "log_id": log_id, "error": str(e)}
            
        except Exception as e:
            logger.error(f"PROCESSING ERROR: Failed to process log {log_id}: {e}")
            db.rollback()
            return {"status": "processing_error", "log_id": log_id, "error": str(e)}
    
    except Exception as e:
        logger.error(f"CRITICAL ERROR in detect_anomaly_task for log {log_id}: {e}")
        return {"status": "critical_error", "log_id": log_id, "error": str(e)}
    finally:
        db.close()


async def analyze_logs_batch_task(ctx, threshold: float = 0.5):
    """
    ARQ cron job to periodically analyze logs that haven't been scored yet.
    """
    logger.info("Starting batch analysis of unscored logs...")
    batch_size = 100
    
    db = next(get_db())
    try:
        unscored_logs = db.query(Log).filter(Log.anomaly_score.is_(None)).limit(batch_size).all()
        if not unscored_logs:
            logger.info("No unscored logs to analyze.")
            return

        logger.info(f"Found {len(unscored_logs)} unscored logs to analyze")
        
        for log in unscored_logs:
            try:
             
                await detect_anomaly_task(ctx, log.data, log.id)
            except Exception as e:
                logger.error(f"Error analyzing log {log.id} in batch: {e}")
                continue
            
        logger.info(f"Finished batch analysis for {len(unscored_logs)} logs.")
    finally:
        db.close()
        

async def compliance_analysis_arq_task(ctx, report_id: int):
    """
    ARQ wrapper for the synchronous compliance analysis service function.
    Manages the database session for the task.
    """
    logger.info(f"Compliance task started for report ID: {report_id}")
    
    db: Session = SessionLocal()
    
    try:
        run_compliance_analysis_task(report_id=report_id, db=db)
        logger.info(f"Compliance task finished successfully for report ID: {report_id}")
        return {"status": "success", "report_id": report_id}
        
    except Exception as e:
        logger.error(f"Compliance task failed for report ID {report_id}: {e}", exc_info=True)
        try:
            from src.models.compliance import ComplianceReport, ReportStatus
            report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
            if report:
                report.status = ReportStatus.FAILED
                report.summary = f"Task execution failed: {str(e)}"
                db.commit()
                logger.info(f"Updated report {report_id} status to FAILED")
        except Exception as update_error:
            logger.error(f"Failed to update report status: {update_error}")
        
        return {"status": "error", "report_id": report_id, "error": str(e)}
        
    finally:
        db.close()

async def retry_failed_compliance_reports(ctx):
    """
    Periodic task to retry failed compliance reports
    """
    logger.info("Checking for failed compliance reports to retry...")
    
    db: Session = SessionLocal()
    try:
        from src.models.compliance import ComplianceReport, ReportStatus
        from datetime import datetime, timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        failed_reports = db.query(ComplianceReport).filter(
            ComplianceReport.status == ReportStatus.FAILED,
            ComplianceReport.updated_at < cutoff_time
        ).limit(5).all() 
        
        if not failed_reports:
            logger.info("No failed compliance reports to retry")
            return {"status": "no_retries_needed"}
        
        logger.info(f"Found {len(failed_reports)} failed reports to retry")
        
        retry_count = 0
        for report in failed_reports:
            try:
                report.status = ReportStatus.PENDING
                report.summary = None
                db.commit()
                
                # Enqueue the task again
                await ctx['redis'].enqueue_job(
                    'compliance_analysis_arq_task',
                    report.id,
                    _job_timeout=300  
                )
                
                retry_count += 1
                logger.info(f"Retrying compliance analysis for report {report.id}")
                
            except Exception as e:
                logger.error(f"Failed to retry report {report.id}: {e}")
                continue
        
        return {"status": "success", "retried_count": retry_count}
        
    except Exception as e:
        logger.error(f"Error in retry_failed_compliance_reports: {e}")
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


class WorkerSettings:
    """
    Optimized ARQ worker configuration for real-time processing and compliance analysis
    """

    functions = [
        detect_anomaly_task, 
        analyze_logs_batch_task, 
        compliance_analysis_arq_task,
        retry_failed_compliance_reports
    ]
    
    # Redis connection settings
    redis_settings = RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://redis:6379/0"))
    
    max_jobs = 20             
    job_timeout = 300           
    keep_result = 600          
    poll_delay = 0.5            
    queue_read_timeout = 2   
    
    # Health check 
    health_check_interval = 30
    health_check_key = "arq:health"
    
    cron_jobs = [
  
        cron(retry_failed_compliance_reports, hour=None, minute=0),  # Every hour
        
        cron(analyze_logs_batch_task, minute={0, 15, 30, 45})  
    ]
