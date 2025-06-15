import logging
from sqlalchemy.orm import Session
from src.models.log import Log
from src.schemas.log import LogCreate 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def store_log(db: Session, log_data: LogCreate) -> Log | None:
    """Stores a log entry in the database from a Pydantic schema."""
    try:
        
        log_entry = Log(
            timestamp=log_data.timestamp,
            source_type=log_data.source_type,
            source_ip=log_data.source_ip,
            data=log_data.data,
            is_anomaly=False, 
            anomaly_score=None,
            threat_type="Normal"
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        logging.info(f"Stored log entry {log_entry.id} ({log_entry.source_type}) in database.")
        return log_entry
    except Exception as e:
        logging.error(f"Error storing log in database: {e}", exc_info=True)
        db.rollback()
        return None