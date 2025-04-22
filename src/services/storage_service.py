# app/services/storage_service.py
import logging
from sqlalchemy.orm import Session
from src.models.log import Log 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def store_log_in_db(processed_log_data: dict, source_type: str, db: Session) -> Log | None:
    """Stores a preprocessed log entry in the database."""
    if not processed_log_data:
         logging.warning("Attempted to store empty processed log data.")
         return None
    try:
        # Ensure timestamp exists and is valid, provide a default if necessary
        timestamp = processed_log_data.get('timestamp')
        if not timestamp:
             logging.warning("Log data missing timestamp, using current time.")
             from datetime import datetime
             timestamp = datetime.now() # Or handle as an error depending on requirements

        log_entry = Log(
            timestamp=timestamp,
            source_type=source_type,
            source_ip=processed_log_data.get('ip_address'), # Use .get for safety
            data=processed_log_data,
            is_anomaly=False, # Initial state
            anomaly_score=None
        )
        db.add(log_entry)
  
        db.flush() 
        db.refresh(log_entry) 
        logging.info(f"Prepared log entry {log_entry.id} ({source_type}) for storage.")
        return log_entry
    except Exception as e:
        logging.error(f"Error preparing log for database ({source_type}): {e}")
      
        return None