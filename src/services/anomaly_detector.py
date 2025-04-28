
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import json
from typing import Dict, Any, Union

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
        
        # If we couldn't find a specific message field, use the entire data as a string
        return str(log_data)
    
    def detect_anomaly(self, log_data: Union[str, Dict[str, Any]], threshold=0.5) -> Dict[str, Any]:
        """
        Detect if a log entry is anomalous.
        
        Args:
            log_data: Either the raw log message or structured log data
            threshold: Score threshold above which a log is considered anomalous
            
        Returns:
            Dict containing anomaly score and boolean flag indicating if it's an anomaly
        """
        # Extract the actual log message if log_data is structured
        if isinstance(log_data, dict) or isinstance(log_data, str) and log_data.startswith('{'):
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
            return {'is_anomaly': False, 'anomaly_score': 0.0}
        
        # Process with the model
        with torch.no_grad():
            # Tokenize the log entry
            inputs = self.tokenizer(log_message, return_tensors="pt", truncation=True, max_length=512).to(self.device)
            
            # Get model predictions
            outputs = self.model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            
            # Assuming binary classification where 1 is anomaly
            anomaly_prob = probabilities[0][1].item()
            is_anomaly = anomaly_prob > threshold
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_prob
            }