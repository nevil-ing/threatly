# src/services/compliance_service.py
import re
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

from src.models.alert import Alert
from src.models.compliance import ComplianceReport, ReportStatus

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceAnalyzer:
    """Singleton class for compliance analysis using Mistral AI"""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ComplianceAnalyzer, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.use_rule_based = False  # Initialize flag
            self._load_model()
            ComplianceAnalyzer._initialized = True
    
    def _load_model(self):
        """Load a lightweight model suitable for ARM VPS with 8GB RAM"""
        try:
            # Use a much smaller model that fits in 8GB RAM
            # Options in order of preference for ARM/low-memory systems:
            model_options = [
                "microsoft/DialoGPT-small",  # ~117MB - Very lightweight
                "distilbert/distilgpt2",     # ~82MB - Ultra lightweight
                "gpt2",                      # ~548MB - Still manageable
            ]
            
            self.HF_TOKEN = os.getenv("HUGGING_FACE_TOKEN")
            model_name = model_options[0]  # Start with the smallest
            
            logger.info(f"Loading lightweight model for compliance analysis: {model_name}")
            logger.info("Using small model optimized for 8GB RAM ARM VPS")
            
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    model_name,
                    token=self.HF_TOKEN if self.HF_TOKEN else None,
                    trust_remote_code=True
                )
                
                # Add padding token if it doesn't exist
                if self.tokenizer.pad_token is None:
                    self.tokenizer.pad_token = self.tokenizer.eos_token
                
                # Load model with minimal memory footprint
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    token=self.HF_TOKEN if self.HF_TOKEN else None,
                    torch_dtype=torch.float32,  # Use float32 for CPU
                    low_cpu_mem_usage=True,     # Optimize for low memory
                    trust_remote_code=True
                )
                
                # Always use CPU for ARM VPS
                self.model.to("cpu")
                logger.info(f"Model {model_name} loaded successfully on CPU")
                
                # Set model to evaluation mode to save memory
                self.model.eval()
                
            except Exception as e:
                logger.warning(f"Failed to load {model_name}, trying fallback: {e}")
                # Fallback to an even smaller model
                fallback_model = "distilbert/distilgpt2"
                logger.info(f"Loading fallback model: {fallback_model}")
                
                self.tokenizer = AutoTokenizer.from_pretrained(fallback_model)
                if self.tokenizer.pad_token is None:
                    self.tokenizer.pad_token = self.tokenizer.eos_token
                
                self.model = AutoModelForCausalLM.from_pretrained(
                    fallback_model,
                    torch_dtype=torch.float32,
                    low_cpu_mem_usage=True
                )
                self.model.to("cpu")
                self.model.eval()
                logger.info(f"Fallback model {fallback_model} loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load any compliance model: {e}")
            # As a last resort, use rule-based analysis
            logger.warning("Falling back to rule-based compliance analysis")
            self.model = None
            self.tokenizer = None
            self.use_rule_based = True
    
    def analyze_compliance(self, alert: Alert, framework: str) -> Dict[str, Any]:
        """
        Analyze an alert for compliance violations using either AI or rule-based approach
        
        Args:
            alert: The security alert to analyze
            framework: The compliance framework to check against
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            logger.info(f"Starting compliance analysis for alert {alert.id} with framework {framework}")
            
            # If model loading failed, use rule-based analysis
            if getattr(self, 'use_rule_based', False) or self.model is None:
                logger.info("Using rule-based compliance analysis")
                return self._rule_based_analysis(alert, framework)
            
            # Create the prompt
            prompt = self._create_compliance_prompt(alert, framework)
            
            # Tokenize input with memory optimization
            inputs = self.tokenizer(
                prompt, 
                return_tensors="pt", 
                padding=True, 
                truncation=True, 
                max_length=1024  # Reduced for memory efficiency
            ).to(self.model.device)
            
            # Generate response with conservative settings
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=256,  # Reduced for memory
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.1,
                    no_repeat_ngram_size=2
                )
            
            # Decode the response
            generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract only the new tokens (remove the input prompt)
            prompt_length = len(self.tokenizer.decode(inputs['input_ids'][0], skip_special_tokens=True))
            llm_output = generated_text[prompt_length:].strip()
            
            logger.info(f"LLM output length: {len(llm_output)} characters")
            
            # Parse the response
            parsed_results = self._parse_llm_json_output(llm_output)
            
            # If parsing fails, fallback to rule-based
            if not parsed_results or not self._validate_compliance_response(parsed_results):
                logger.warning("LLM parsing failed, falling back to rule-based analysis")
                return self._rule_based_analysis(alert, framework)
            
            logger.info(f"Compliance analysis completed for alert {alert.id}")
            return parsed_results
            
        except Exception as e:
            logger.error(f"Error during AI compliance analysis: {e}, falling back to rule-based")
            return self._rule_based_analysis(alert, framework)
    
    def _create_compliance_prompt(self, alert: Alert, framework: str) -> str:
        """Create a structured prompt for compliance analysis"""
        
        # Map common frameworks to more detailed descriptions
        framework_details = {
            "GDPR": "General Data Protection Regulation - focuses on data protection and privacy",
            "HIPAA": "Health Insurance Portability and Accountability Act - healthcare data protection",
            "PCI-DSS": "Payment Card Industry Data Security Standard - payment card data protection",
            "SOX": "Sarbanes-Oxley Act - financial reporting and corporate governance",
            "NIST": "NIST Cybersecurity Framework - comprehensive cybersecurity standards",
            "ISO27001": "ISO/IEC 27001 - information security management systems"
        }
        
        framework_desc = framework_details.get(framework, f"{framework} compliance framework")
        
        alert_details = f"""
Alert ID: {alert.id}
Threat Type: {alert.threat_type or 'Unknown'}
Severity: {alert.severity or 'Unknown'}
Description: {alert.description or 'No description available'}
Source IP: {alert.source_ip or 'Unknown'}
Timestamp: {alert.created_at.isoformat() if alert.created_at else 'Unknown'}
Log Source: {getattr(alert, 'log_source', 'Unknown')}
"""

        prompt = f"""<s>[INST] You are a senior cybersecurity compliance analyst with expertise in {framework_desc}. 

Analyze the following security alert and determine if it represents a potential violation of {framework} requirements.

**Security Alert Details:**
{alert_details}

**Analysis Requirements:**
1. Determine if this alert indicates a potential {framework} violation
2. Provide a clear, concise summary of your findings
3. If it's a violation, specify which {framework} requirements/controls are affected
4. Recommend specific, actionable remediation steps

**Response Format:**
Respond with ONLY a valid JSON object in this exact format:
{{
  "isViolation": boolean,
  "summary": "Brief summary of analysis findings",
  "violationDetails": "Specific framework requirements violated (or null if no violation)",
  "recommendedActions": "Concrete remediation steps (or null if no violation)"
}}

Do not include any text before or after the JSON object. [/INST]

</s>"""
        
        return prompt
    
    def _parse_llm_json_output(self, llm_text: str) -> Dict[str, Any]:
        """Parse JSON output from LLM response with multiple fallback strategies"""
        
        # Strategy 1: Look for JSON block between curly braces
        json_patterns = [
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',  # Nested JSON
            r'\{.*?\}',  # Simple JSON (non-greedy)
            r'\{.*\}'    # Simple JSON (greedy)
        ]
        
        for pattern in json_patterns:
            json_match = re.search(pattern, llm_text, re.DOTALL)
            if json_match:
                try:
                    json_str = json_match.group(0)
                    # Clean up common JSON formatting issues
                    json_str = self._clean_json_string(json_str)
                    parsed = json.loads(json_str)
                    
                    # Validate required fields
                    if self._validate_compliance_response(parsed):
                        logger.info("Successfully parsed JSON response from LLM")
                        return parsed
                        
                except json.JSONDecodeError as e:
                    logger.warning(f"JSON decode error with pattern {pattern}: {e}")
                    continue
        
        # Strategy 2: Try to extract key-value pairs manually
        logger.warning("Failed to parse JSON, attempting manual extraction")
        return self._extract_fields_manually(llm_text)
    
    def _clean_json_string(self, json_str: str) -> str:
        """Clean common JSON formatting issues"""
        # Remove any markdown code block markers
        json_str = re.sub(r'```json\s*', '', json_str)
        json_str = re.sub(r'```\s*$', '', json_str)
        
        # Fix common quote escaping issues
        json_str = json_str.replace('\\"', '"')
        json_str = json_str.replace("'", '"')  # Replace single quotes with double quotes
        
        # Remove any trailing commas
        json_str = re.sub(r',\s*}', '}', json_str)
        json_str = re.sub(r',\s*]', ']', json_str)
        
        return json_str.strip()
    
    def _validate_compliance_response(self, response: Dict[str, Any]) -> bool:
        """Validate that the response contains required fields"""
        required_fields = ['isViolation', 'summary']
        return all(field in response for field in required_fields)
    
    def _rule_based_analysis(self, alert: Alert, framework: str) -> Dict[str, Any]:
        """
        Rule-based compliance analysis as fallback when AI model is not available
        """
        logger.info(f"Performing rule-based compliance analysis for {framework}")
        
        threat_type = (alert.threat_type or "").lower()
        severity = (alert.severity or "").lower()
        description = (alert.description or "").lower()
        
        # Framework-specific rule sets
        framework_rules = {
            "GDPR": {
                "data_breach_indicators": ["data breach", "personal data", "pii", "privacy", "unauthorized access"],
                "high_risk_threats": ["sql injection", "xss", "data exfiltration", "credential theft"],
                "violation_threshold": "medium"
            },
            "HIPAA": {
                "data_breach_indicators": ["phi", "health", "medical", "patient data", "healthcare"],
                "high_risk_threats": ["unauthorized access", "data breach", "malware", "ransomware"],
                "violation_threshold": "low"
            },
            "PCI-DSS": {
                "data_breach_indicators": ["payment", "card", "financial", "transaction", "credit card"],
                "high_risk_threats": ["sql injection", "payment fraud", "card skimming", "financial malware"],
                "violation_threshold": "medium"
            },
            "SOX": {
                "data_breach_indicators": ["financial", "audit", "accounting", "financial records"],
                "high_risk_threats": ["data manipulation", "unauthorized access", "privilege escalation"],
                "violation_threshold": "high"
            },
            "NIST": {
                "data_breach_indicators": ["security incident", "breach", "compromise", "unauthorized"],
                "high_risk_threats": ["malware", "ddos", "injection", "privilege escalation"],
                "violation_threshold": "medium"
            },
            "ISO27001": {
                "data_breach_indicators": ["information security", "data breach", "security incident"],
                "high_risk_threats": ["malware", "phishing", "insider threat", "data breach"],
                "violation_threshold": "medium"
            }
        }
        
        rules = framework_rules.get(framework, framework_rules["NIST"])  # Default to NIST
        
        # Check for indicators
        is_violation = False
        violation_reasons = []
        
        # Check threat type
        if any(indicator in threat_type for indicator in rules["high_risk_threats"]):
            is_violation = True
            violation_reasons.append(f"High-risk threat type detected: {alert.threat_type}")
        
        # Check description for data breach indicators
        if any(indicator in description for indicator in rules["data_breach_indicators"]):
            is_violation = True
            violation_reasons.append(f"Data breach indicators found in alert description")
        
        # Check severity threshold
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold_scores = {"low": 1, "medium": 2, "high": 3}
        
        alert_severity_score = severity_scores.get(severity, 2)
        threshold_score = threshold_scores.get(rules["violation_threshold"], 2)
        
        if alert_severity_score >= threshold_score:
            is_violation = True
            violation_reasons.append(f"Alert severity ({severity}) meets {framework} threshold")
        
        # Generate response
        if is_violation:
            summary = f"Potential {framework} compliance violation detected based on rule-based analysis"
            violation_details = "; ".join(violation_reasons)
            recommended_actions = self._get_framework_recommendations(framework)
        else:
            summary = f"No {framework} compliance violation detected based on rule-based analysis"
            violation_details = None
            recommended_actions = None
        
        return {
            "isViolation": is_violation,
            "summary": summary,
            "violationDetails": violation_details,
            "recommendedActions": recommended_actions,
            "analysis_method": "rule_based"
        }
    
    def _get_framework_recommendations(self, framework: str) -> str:
        """Get standard recommendations for each framework"""
        recommendations = {
            "GDPR": "1. Notify data protection authority within 72 hours; 2. Implement additional data encryption; 3. Review access controls and audit logs",
            "HIPAA": "1. Report breach to HHS within 60 days; 2. Notify affected individuals; 3. Implement additional PHI safeguards",
            "PCI-DSS": "1. Isolate affected systems; 2. Notify payment processors; 3. Conduct forensic investigation",
            "SOX": "1. Preserve audit trail; 2. Notify auditors; 3. Review financial controls and access",
            "NIST": "1. Contain and eradicate threat; 2. Update security controls; 3. Conduct lessons learned review",
            "ISO27001": "1. Activate incident response plan; 2. Review and update risk assessment; 3. Implement corrective actions"
        }
        return recommendations.get(framework, recommendations["NIST"])
        """Manual field extraction as fallback"""
        result = {
            "isViolation": True,  # Conservative default
            "summary": "Unable to parse LLM response properly",
            "violationDetails": None,
            "recommendedActions": None
        }
        
        # Look for boolean indicators
        violation_indicators = ['violation', 'breach', 'non-compliant', 'violates']
        no_violation_indicators = ['compliant', 'no violation', 'not a violation']
        
        text_lower = text.lower()
        
        if any(indicator in text_lower for indicator in no_violation_indicators):
            result["isViolation"] = False
        
        # Try to extract summary from common patterns
        summary_patterns = [
            r'summary["\']?\s*:\s*["\']([^"\']+)["\']',
            r'summary[:\s]+([^.]+\.)+'
        ]
        
        for pattern in summary_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                result["summary"] = match.group(1).strip()
                break
        
        return result


# Global instance
compliance_analyzer = ComplianceAnalyzer()

def run_compliance_analysis_task(report_id: int, db: Session):
    """
    Background task for compliance analysis - called by ARQ worker
    """
    logger.info(f"Starting compliance analysis task for report ID: {report_id}")
    
    # Fetch the report
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        logger.error(f"Report ID {report_id} not found")
        return
    
    # Set status to processing
    report.status = ReportStatus.PROCESSING
    db.commit()
    
    try:
        # Fetch the associated alert
        alert = db.query(Alert).filter(Alert.id == report.alert_id).first()
        if not alert:
            raise ValueError(f"Associated alert {report.alert_id} not found")
        
        logger.info(f"Analyzing alert {alert.id} for {report.framework} compliance")
        
        # Run the analysis
        analysis_results = compliance_analyzer.analyze_compliance(alert, report.framework)
        
        # Update the report with results
        report.is_violation = analysis_results.get("isViolation", False)
        report.summary = analysis_results.get("summary", "No summary provided")
        report.violation_details = analysis_results.get("violationDetails")
        report.recommended_actions = analysis_results.get("recommendedActions")
        report.status = ReportStatus.COMPLETED
        report.completed_at = datetime.utcnow()
        
        logger.info(f"Compliance analysis completed for report {report_id}. Violation: {report.is_violation}")
        
    except Exception as e:
        logger.error(f"Compliance analysis failed for report {report_id}: {e}", exc_info=True)
        report.status = ReportStatus.FAILED
        report.summary = f"Analysis failed: {str(e)}"
        
    finally:
        db.commit()
        logger.info(f"Compliance analysis task completed for report ID: {report_id}")


# Utility functions for testing and management
def test_compliance_analysis(alert_id: int, framework: str, db: Session) -> Dict[str, Any]:
    """Test function for compliance analysis"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")
    
    return compliance_analyzer.analyze_compliance(alert, framework)

def get_model_status() -> Dict[str, Any]:
    """Get status of the compliance model"""
    try:
        model_loaded = hasattr(compliance_analyzer, 'model') and compliance_analyzer.model is not None
        tokenizer_loaded = hasattr(compliance_analyzer, 'tokenizer') and compliance_analyzer.tokenizer is not None
        
        device = str(compliance_analyzer.model.device) if model_loaded else "Unknown"
        model_name = "mistralai/Mistral-7B-Instruct-v0.2" if model_loaded else "Not loaded"
        
        return {
            "model_loaded": model_loaded,
            "tokenizer_loaded": tokenizer_loaded,
            "device": device,
            "model_name": model_name,
            "cuda_available": torch.cuda.is_available(),
            "hf_token_configured": bool(os.getenv("HUGGING_FACE_TOKEN"))
        }
    except Exception as e:
        return {
            "error": str(e),
            "model_loaded": False,
            "status": "error"
        }