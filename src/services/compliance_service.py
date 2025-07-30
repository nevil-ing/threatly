# src/services/compliance.py
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import json
from datetime import datetime
from sqlalchemy.orm import Session
from src.models.alert import Alert
from src.models.compliance import ComplianceReport, ReportStatus

# --- LLM and Tokenizer Setup ---
# This is okay for a single worker, but for scaling, consider a dedicated inference server.
tokenizer = AutoTokenizer.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")
model = AutoModelForCausalLM.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")
model.to("cpu") # Use "cuda" if you have a GPU

# --- THE BACKGROUND TASK ---
def run_compliance_analysis_task(report_id: int, db: Session):
    """
    This is the background task that performs the actual LLM analysis.
    It should be called by your worker (e.g., ARQ).
    """
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        print(f"Error: Report ID {report_id} not found.")
        return

    # Set status to Processing
    report.status = ReportStatus.PROCESSING
    db.commit()

    try:
        # Fetch the alert data from the database
        alert = db.query(Alert).filter(Alert.id == report.alert_id).first()
        if not alert:
            raise ValueError("Associated alert not found.")

        # --- Enhanced Prompt Engineering ---
        prompt = create_compliance_prompt(alert, report.framework)
        
        # Run LLM inference
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        outputs = model.generate(**inputs, max_new_tokens=1024, do_sample=True, temperature=0.3)
        llm_output_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Extract the JSON part of the response
        parsed_results = parse_llm_json_output(llm_output_text)

        # Update the report with the results
        report.is_violation = parsed_results.get("isViolation", False)
        report.summary = parsed_results.get("summary", "No summary provided.")
        report.violation_details = parsed_results.get("violationDetails", None)
        report.recommended_actions = parsed_results.get("recommendedActions", None)
        report.status = ReportStatus.COMPLETED
        report.completed_at = datetime.utcnow()

    except Exception as e:
        print(f"Failed to analyze compliance for report {report_id}: {e}")
        report.status = ReportStatus.FAILED
        report.summary = f"Analysis failed: {str(e)}"
    
    finally:
        db.commit()

# --- Helper function for prompt creation ---
def create_compliance_prompt(alert: Alert, framework: str) -> str:
    alert_details = f"""
    - Threat Type: {alert.threat_type}
    - Severity: {alert.severity}
    - Description: {alert.description}
    - Source IP: {alert.source_ip}
    - Timestamp: {alert.created_at.isoformat()}
    """

    prompt = f"""
[INST]
You are a senior cybersecurity compliance analyst. Your task is to analyze a security alert based on the '{framework}' framework and provide a structured JSON response.

**Security Alert Details:**
{alert_details}

**Your Task:**
1.  **Analyze Violation:** Determine if the alert indicates a potential violation of the '{framework}' framework.
2.  **Provide Summary:** Write a brief, clear summary of your findings.
3.  **Detail Violation:** If it is a violation, explain which specific articles or controls of '{framework}' are potentially breached and why.
4.  **Recommend Actions:** Suggest 2-3 concrete, actionable steps to mitigate this issue and improve compliance.

**Output Format:**
Provide your response ONLY in the following JSON format. Do not add any text before or after the JSON block.
{{
  "isViolation": boolean,
  "summary": "string",
  "violationDetails": "string (or null if no violation)",
  "recommendedActions": "string (or null if no violation)"
}}
[/INST]
"""
    return prompt

# --- Helper function to parse LLM output ---
def parse_llm_json_output(llm_text: str) -> dict:
    # Find the start and end of the JSON block
    json_match = re.search(r'\{.*\}', llm_text, re.DOTALL)
    if not json_match:
        # Fallback if no JSON is found
        return {"summary": llm_text, "isViolation": True} # Assume violation if format is wrong
    
    try:
        return json.loads(json_match.group(0))
    except json.JSONDecodeError:
        # Fallback if JSON is malformed
        return {"summary": "LLM returned malformed JSON.", "isViolation": True}