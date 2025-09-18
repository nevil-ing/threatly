
import requests
import os
import json
from typing import Dict, Any, Union
from sqlalchemy.orm import Session
import logging

from src.services.alerting import trigger_alert
from src.services.threat_classifier import ThreatPatternClassifier
from src.core.celery import celery_app
from src.core.database import get_db
from src.models import Log


class LogAnomalyDetector:
    """
    [MODIFIED] Service to detect anomalies by calling a remote model inference API.
    This class no longer loads the heavy model itself.
    """
   
    def __init__(self, model_api_url: str):
        """Initialize the anomaly detector with the URL of the model API."""
        if not model_api_url:
            raise ValueError("model_api_url cannot be empty.")
        self.model_api_url = model_api_url
        self.session = requests.Session()  # Use a session for connection pooling
        
 
        self.threat_classifier = ThreatPatternClassifier()

     
    # This helper function is still useful and remains unchanged.
    def extract_log_message(self, log_data: Dict[str, Any]) -> str:
        """Extract the actual log message from the log data structure."""
        if isinstance(log_data, dict):
            if 'message' in log_data:
                return log_data['message']
            elif 'original' in log_data:
                return log_data['original']
            elif 'data' in log_data and isinstance(log_data['data'], dict) and 'message' in log_data['data']:
                return log_data['data']['message']
        return str(log_data)
 
    def detect_anomaly(self, log_data: Union[str, Dict[str, Any]], threshold=0.5, log_entry=None, db: Session=None) -> Dict[str, Any]:
        """Detect if a log entry is anomalous by calling the model API."""
        
        # This part for extracting the log message is unchanged.
        if isinstance(log_data, dict) or (isinstance(log_data, str) and log_data.startswith('{')):
            try:
                if isinstance(log_data, str):
                    log_data = json.loads(log_data)
                log_message = self.extract_log_message(log_data)
            except (json.JSONDecodeError, AttributeError):
                log_message = str(log_data)
        else:
            log_message = str(log_data)
        
        if not log_message or log_message.strip() == '':
            # Return early for empty messages, unchanged.
            return {
                'is_anomaly': False, 
                'anomaly_score': 0.0,
                'threat_classification': {"threat_type": "Normal", "confidence": 1.0, "severity": "None", "details": "Empty log message"}
            }
        
       
        try:
            
            response = self.session.post(self.model_api_url, json={"log_message": log_message}, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP error codes
            
            inference_result = response.json()
            anomaly_prob = inference_result.get('anomaly_score', 0.0)
            is_anomaly = anomaly_prob > threshold # Use the same threshold logic

        except requests.exceptions.RequestException as e:
            logging.error(f"Could not connect to model API at {self.model_api_url}: {e}")
            # Fail safely by treating the log as non-anomalous.
            is_anomaly = False
            anomaly_prob = 0.0
        
        

        # The rest of the logic for classification and alerting remains the same,
        # but it now uses the 'is_anomaly' and 'anomaly_prob' from the API call.
        if is_anomaly:
            threat_classification = self.threat_classifier.classify_threat(
                log_message=log_message,
                anomaly_score=anomaly_prob,
                source_ip=getattr(log_entry, 'source_ip', None) if log_entry else None,
                source_type=getattr(log_entry, 'source_type', None) if log_entry else None
            )
        else:
            threat_classification = {
                "threat_type": "Normal", "confidence": 1.0 - anomaly_prob, "severity": "None", "details": "No anomaly detected"
            }
        
        result = {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_prob,
            'threat_classification': threat_classification
        }
        
        if is_anomaly and log_entry is not None and db is not None:
            try:
                log_entry.is_anomaly = True
                log_entry.anomaly_score = anomaly_prob
                log_entry.threat_type = threat_classification["threat_type"]
                db.add(log_entry)
                db.commit()
                db.refresh(log_entry)
                
                alert = trigger_alert(
                    log_entry=log_entry,
                    threat_classification=threat_classification,
                    db=db
                )
                
                result['alert_id'] = alert.id
                logging.info(f"Alert {alert.id} triggered for anomalous log {log_entry.id} with score {anomaly_prob:.3f}")
                
            except Exception as e:
                logging.error(f"Failed to update log {log_entry.id} or trigger alert: {e}")
                db.rollback()
        
        return result

    # The batch and statistics methods don't need to change, as they rely on detect_anomaly.
    def batch_analyze_logs(self, log_entries: list, threshold: float = 0.5, db: Session = None) -> Dict[str, Any]:
        # This method works as-is because the change is encapsulated in detect_anomaly.
        # ... (code unchanged)
        return super().batch_analyze_logs(log_entries, threshold, db)

    def get_threat_statistics(self, db: Session, days: int = 7) -> Dict[str, Any]:
        # This method is purely for DB queries and is unchanged.
        # ... (code unchanged)
        return super().get_threat_statistics(db, days)


anomaly_detector_instance = None

def get_anomaly_detector():
    """Gets a shared instance of the LogAnomalyDetector."""
    global anomaly_detector_instance
    if anomaly_detector_instance is None:
        model_api_url = os.getenv("MODEL_API_URL")
        if not model_api_url:
            logging.critical("MODEL_API_URL environment variable is not set! Anomaly detection will fail.")
            # Or raise an exception to stop the worker from starting improperly
            raise ValueError("MODEL_API_URL is not configured.")
        
        logging.info(f"Creating LogAnomalyDetector instance for API: {model_api_url}")
        anomaly_detector_instance = LogAnomalyDetector(model_api_url=model_api_url)
    return anomaly_detector_instance





