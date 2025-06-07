import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import json
from typing import Dict, Any, Union
from src.services.alerting import trigger_alert
from sqlalchemy.orm import Session
import logging
from src.services.threat_classifier import ThreatPatternClassifier

class LogAnomalyDetector:
    """Service to detect anomalies in logs using a pre-trained transformer model."""
    
    def __init__(self, model_name="Dumi2025/log-anomaly-detection-model-new"):
        """Initialize the anomaly detector with the specified model."""
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Initializing anomaly detector with model {model_name} on {self.device}")
        
        # Load model and tokenizer from Hugging Face
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name).to(self.device)
        self.model.eval()
        
        # Initialize threat classifier
        self.threat_classifier = ThreatPatternClassifier()
    
    def extract_log_message(self, log_data: Dict[str, Any]) -> str:
        """Extract the actual log message from the log data structure."""
        if isinstance(log_data, dict):
            # If data is in JSON format, extract the relevant log message
            if 'message' in log_data:
                return log_data['message']
            elif 'original' in log_data:
                return log_data['original']
            elif 'data' in log_data and isinstance(log_data['data'], dict) and 'message' in log_data['data']:
                return log_data['data']['message']
        
        
        return str(log_data)
    
    def detect_anomaly(self, log_data: Union[str, Dict[str, Any]], threshold=0.5, log_entry=None, db: Session=None) -> Dict[str, Any]:
        """
        Detect if a log entry is anomalous and classify threat type.
        
        Args:
            log_data: Either the raw log message or structured log data
            threshold: Score threshold above which a log is considered anomalous
            log_entry: Optional database log entry object to update
            db: Optional database session for persistence
            
        Returns:
            Dict containing anomaly score, boolean flag, and threat classification
        """
        # Extract the actual log message if log_data is structured
        if isinstance(log_data, dict) or (isinstance(log_data, str) and log_data.startswith('{')):
            try:
                if isinstance(log_data, str):
                    log_data = json.loads(log_data)
                log_message = self.extract_log_message(log_data)
            except (json.JSONDecodeError, AttributeError):
                log_message = str(log_data)
        else:
            log_message = str(log_data)
        
        # Skip empty messages
        if not log_message or log_message.strip() == '':
            return {
                'is_anomaly': False, 
                'anomaly_score': 0.0,
                'threat_classification': {
                    "threat_type": "Normal",
                    "confidence": 1.0,
                    "severity": "None",
                    "details": "Empty log message"
                }
            }
        
        # Process with the model
        with torch.no_grad():
            # Tokenize the log entry
            inputs = self.tokenizer(log_message, return_tensors="pt", truncation=True, max_length=512).to(self.device)
            
            # Get model predictions
            outputs = self.model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            
            # Assuming binary classification where 1 is anomaly
            anomaly_prob = probabilities[0][1].item() if probabilities.shape[1] > 1 else probabilities[0][0].item()
            is_anomaly = anomaly_prob > threshold
            
            # Classify threat type using pattern-based classifier
            if is_anomaly:
                threat_classification = self.threat_classifier.classify_threat(
                    log_message=log_message,
                    anomaly_score=anomaly_prob,
                    source_ip=getattr(log_entry, 'source_ip', None) if log_entry else None,
                    source_type=getattr(log_entry, 'source_type', None) if log_entry else None
                )
            else:
                threat_classification = {
                    "threat_type": "Normal",
                    "confidence": 1.0 - anomaly_prob,
                    "severity": "None",
                    "details": "No anomaly detected"
                }
            
            result = {
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_prob,
                'threat_classification': threat_classification
            }
            
            # Update database and trigger enhanced alerts
            if is_anomaly and log_entry is not None and db is not None:
                try:
                    # Update the log entry with anomaly information
                    log_entry.is_anomaly = True
                    log_entry.anomaly_score = anomaly_prob
                    log_entry.threat_type = threat_classification["threat_type"]
                    db.add(log_entry)
                    db.commit()
                    db.refresh(log_entry)
                    
                    # Trigger the enhanced alert with threat classification
                    alert = trigger_alert(
                        log_entry=log_entry,
                        threat_classification=threat_classification,
                        db=db
                    )
                    
                    result['alert_id'] = alert.id
                    logging.info(f"Alert {alert.id} triggered for anomalous log {log_entry.id} with score {anomaly_prob:.3f}")
                    logging.info(f"Enhanced alert {alert.id} triggered for {threat_classification['threat_type']} with severity {threat_classification['severity']}")
                    
                except Exception as e:
                    logging.error(f"Failed to update log {log_entry.id} or trigger alert: {e}")
                    db.rollback()
            
            return result
    
    def batch_analyze_logs(self, log_entries: list, threshold: float = 0.5, db: Session = None) -> Dict[str, Any]:
        """
        Analyze multiple log entries in batch for better performance.
        
        Args:
            log_entries: List of log entries to analyze
            threshold: Anomaly detection threshold
            db: Database session for persistence
            
        Returns:
            Dict containing batch analysis results
        """
        results = {
            'total_processed': 0,
            'anomalies_detected': 0,
            'threat_summary': {},
            'failed_analyses': 0
        }
        
        for log_entry in log_entries:
            try:
                result = self.detect_anomaly(
                    log_data=log_entry.data,
                    threshold=threshold,
                    log_entry=log_entry,
                    db=db
                )
                
                results['total_processed'] += 1
                
                if result['is_anomaly']:
                    results['anomalies_detected'] += 1
                    threat_type = result['threat_classification']['threat_type']
                    
                    if threat_type not in results['threat_summary']:
                        results['threat_summary'][threat_type] = 0
                    results['threat_summary'][threat_type] += 1
                
            except Exception as e:
                logging.error(f"Failed to analyze log {log_entry.id}: {e}")
                results['failed_analyses'] += 1
        
        logging.info(f"Batch analysis completed: {results['total_processed']} logs processed, {results['anomalies_detected']} anomalies detected")
        return results
    
    def get_threat_statistics(self, db: Session, days: int = 7) -> Dict[str, Any]:
        """
        Get threat statistics for the specified time period.
        
        Args:
            db: Database session
            days: Number of days to look back
            
        Returns:
            Dict containing threat statistics
        """
        from datetime import datetime, timedelta
        from src.models.log import Log
        from src.models.alert import Alert
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get anomaly statistics
        total_logs = db.query(Log).filter(Log.created_at >= start_date).count()
        anomalous_logs = db.query(Log).filter(
            Log.created_at >= start_date,
            Log.is_anomaly == True
        ).count()
        
        # Get threat type distribution
        threat_distribution = db.query(Log.threat_type, db.func.count(Log.id)).filter(
            Log.created_at >= start_date,
            Log.is_anomaly == True
        ).group_by(Log.threat_type).all()
        
        # Get alert statistics
        total_alerts = db.query(Alert).filter(Alert.created_at >= start_date).count()
        open_alerts = db.query(Alert).filter(
            Alert.created_at >= start_date,
            Alert.status == "Open"
        ).count()
        
        return {
            'period_days': days,
            'total_logs': total_logs,
            'anomalous_logs': anomalous_logs,
            'anomaly_rate': (anomalous_logs / total_logs * 100) if total_logs > 0 else 0,
            'threat_distribution': dict(threat_distribution),
            'total_alerts': total_alerts,
            'open_alerts': open_alerts,
            'generated_at': datetime.utcnow().isoformat()
        }