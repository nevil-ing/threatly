# app/services/ai_ml/ingestion.py
import logging
from sqlalchemy.orm import Session

from src.services.preprocessing import preprocess_log_message
from src.services.storage_service import store_log_in_db
from src.services.alerting import trigger_alert
#from .ai_ml import detect_log_anomaly
from src.core.database import SessionLocal

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def process_raw_log_line(raw_line: str, source_type: str):
    """
    Orchestrates the processing of a raw log line.
    1. Preprocesses the log.
    2. Stores the processed log.
    3. Triggers anomaly detection.
    4. Triggers alerting if anomaly detected.
    """
    logging.debug(f"Received raw log ({source_type}): {raw_line}")

    # 1. Preprocess
    processed_data = preprocess_log_message(raw_line, source_type)
    if not processed_data:
        logging.warning(f"Failed to preprocess log line ({source_type}): {raw_line}")
        return

    # Create a database session for this log line's transaction
    db: Session = SessionLocal()
    log_entry_from_db = None
    try:
        # 2. Store Log
        log_entry_from_db = store_log_in_db(processed_data, source_type, db)
        if not log_entry_from_db:
            # Storage failed, error already logged by store_log_in_db
            return # Don't proceed
        '''
        # 3. Anomaly Detection
        is_anomaly, anomaly_score = detect_log_anomaly(processed_data) # Use processed data

        # 4. Update Log with Anomaly Info (if detected) & Trigger Alert
        if is_anomaly:
            try:
                log_entry_from_db.is_anomaly = True
                log_entry_from_db.anomaly_score = anomaly_score
                db.add(log_entry_from_db)
                db.commit() # Commit the anomaly update
                db.refresh(log_entry_from_db)
                logging.info(f"Updated log {log_entry_from_db.id} with anomaly data.")
                # Trigger alert AFTER successfully updating the log
                trigger_alert(log_entry=log_entry_from_db, db=db)
            except Exception as e:
                 logging.error(f"Failed to update log {log_entry_from_db.id} with anomaly info or trigger alert: {e}")
                 db.rollback()
        '''
    except Exception as e:
         logging.error(f"Unexpected error during log processing pipeline: {e}")
         db.rollback() 
    finally:
        db.close() 