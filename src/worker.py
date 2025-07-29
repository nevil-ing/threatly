# src/worker.py
import os
import requests
import logging
from arq import cron
from arq.connections import RedisSettings
from sqlalchemy.orm import Session
from src.core.database import get_db
from src.models import Log

# Helper classes (can be moved to a shared location)
from src.services.alerting import trigger_alert
from src.services.threat_classifier import ThreatPatternClassifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Singleton Pattern for helper classes (more efficient) ---
# We load these once per worker process, not on every task.
threat_classifier = ThreatPatternClassifier()
http_session = requests.Session()
MODEL_API_URL = os.getenv("MODEL_API_URL")

if not MODEL_API_URL:
    logger.error("MODEL_API_URL environment variable is not set!")
    raise ValueError("MODEL_API_URL is required for anomaly detection")

# ARQ Task Definition

async def detect_anomaly_task(ctx, log_data: dict, log_id: int):
    """
    ARQ task to analyze a single log entry in real-time.
    This function should execute immediately when a log is received.
    """
    start_time = ctx.get('job_start_time') if hasattr(ctx, 'get') else None
    logger.info(f"🚀 REAL-TIME DETECTION: Starting anomaly detection for log ID: {log_id}")
    
    # Database logic remains synchronous here. For high performance, you'd use an async DB driver.
    db = next(get_db())
    try:
        log_entry = db.query(Log).filter(Log.id == log_id).first()
        if not log_entry:
            logger.error(f"❌ CRITICAL: Log ID {log_id} not found for analysis!")
            return {"status": "error", "message": "Log not found"}
        
        # Extract log message for analysis - more robust extraction
        log_message = ""
        if isinstance(log_data, dict):
            # Try multiple possible keys for the log message
            for key in ['message', 'data', 'log_message', 'content', 'text']:
                if key in log_data:
                    if isinstance(log_data[key], dict):
                        # If it's nested, try to extract message from nested dict
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
        
        logger.info(f"📝 Analyzing message: {log_message[:100]}{'...' if len(log_message) > 100 else ''}")
        
        # Call model API for real-time analysis
        try:
            logger.info(f"🔍 Calling model API for REAL-TIME analysis of log ID {log_id}")
            
            # Use shorter timeout for real-time processing
            response = http_session.post(
                MODEL_API_URL, 
                json={"log_message": log_message}, 
                timeout=5  # Reduced timeout for real-time
            )
            response.raise_for_status()
            result = response.json()
            anomaly_score = result.get('anomaly_score', 0.0)
            
            logger.info(f"📊 Log ID {log_id}: anomaly_score = {anomaly_score}")

            # Update log entry with anomaly score
            log_entry.anomaly_score = anomaly_score
            
            if anomaly_score > 0.5:  # Anomaly detected
                logger.warning(f"🚨 THREAT DETECTED! Log ID {log_id} with score {anomaly_score}")
                log_entry.is_anomaly = True
                
                # Use the threat classifier
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
                    logger.critical(f"🚨 ALERT TRIGGERED: Alert {alert.id} for anomalous log ID: {log_id}")
                    db.commit()
            
                    logger.critical(f"✅ TRANSACTION COMMITTED. Alert {alert.id} created for anomalous log ID: {log_id}")
                    return {
                        "status": "threat_detected",
                        "log_id": log_id,
                        "anomaly_score": anomaly_score,
                        "threat_type": threat_info.get("threat_type"),
                        "alert_id": alert.id,
                        "is_anomaly": True
                    }
                except Exception as alert_error:
                    logger.error(f"❌ Failed to trigger alert for log {log_id}: {alert_error}")
                    return {
                        "status": "threat_detected_no_alert",
                        "log_id": log_id,
                        "anomaly_score": anomaly_score,
                        "is_anomaly": True
                    }
            else:
                logger.info(f"✅ No threat detected for log ID {log_id}")
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
            logger.error(f"⏱️ TIMEOUT: Model API call timed out for log {log_id}")
            # For real-time systems, timeouts are critical
            log_entry.anomaly_score = 0.0
            log_entry.is_anomaly = False
            log_entry.threat_type = "API_Timeout"
            db.commit()
            return {"status": "timeout", "log_id": log_id}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ API ERROR: Failed to call model API for log {log_id}: {e}")
            # Mark as analyzed but with error
            log_entry.anomaly_score = 0.0
            log_entry.is_anomaly = False
            log_entry.threat_type = "API_Error"
            db.commit()
            return {"status": "api_error", "log_id": log_id, "error": str(e)}
            
        except Exception as e:
            logger.error(f"❌ PROCESSING ERROR: Failed to process log {log_id}: {e}")
            db.rollback()
            return {"status": "processing_error", "log_id": log_id, "error": str(e)}
    
    except Exception as e:
        logger.error(f"❌ CRITICAL ERROR in detect_anomaly_task for log {log_id}: {e}")
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
                # We can call the single-log analysis task directly.
                # This keeps logic centralized.
                await detect_anomaly_task(ctx, log.data, log.id)
            except Exception as e:
                logger.error(f"Error analyzing log {log.id} in batch: {e}")
                continue
            
        logger.info(f"Finished batch analysis for {len(unscored_logs)} logs.")
    finally:
        db.close()


# ARQ Worker Configuration
class WorkerSettings:
    # List of functions that this worker can execute.
    functions = [detect_anomaly_task, analyze_logs_batch_task]
    
    # Redis connection settings, read from environment or default to 'redis'.
    redis_settings = RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://redis:6379/0"))
    
    # OPTIMIZED FOR REAL-TIME PROCESSING
    max_jobs = 20               # Allow more concurrent jobs for real-time processing
    job_timeout = 30            # Shorter timeout for real-time (30 seconds)
    keep_result = 300           # Keep results for 5 minutes (shorter for real-time)
    poll_delay = 0.5            # Check for new jobs every 0.5 seconds (faster polling)
    queue_read_timeout = 1      # Shorter queue read timeout for responsiveness
    
    # Health check settings
    health_check_interval = 30
    health_check_key = "arq:health"