# model_api/app.py
from fastapi import FastAPI, Request, HTTPException
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Model Inference API")


try:
    MODEL_NAME = "Dumi2025/log-anomaly-detection-model-new"
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    logger.info(f"Loading tokenizer for model: {MODEL_NAME}")
    TOKENIZER = AutoTokenizer.from_pretrained(MODEL_NAME)
    
    logger.info(f"Loading model {MODEL_NAME} onto device: {DEVICE}")
    MODEL = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME).to(DEVICE)
    MODEL.eval() 
    
    logger.info("Model loaded successfully.")

except Exception as e:
    logger.error(f"Failed to load model: {e}")
   
    TOKENIZER = None
    MODEL = None



@app.post("/infer")
async def infer(request: Request):
    if not MODEL or not TOKENIZER:
        raise HTTPException(status_code=503, detail="Model is not available.")

    try:
        data = await request.json()
        log_message = data.get("log_message", "")

        if not log_message:
            return {"is_anomaly": False, "anomaly_score": 0.0}

        # Perform inference
        with torch.no_grad():
            inputs = TOKENIZER(log_message, return_tensors="pt", truncation=True, max_length=512).to(DEVICE)
            outputs = MODEL(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            
            anomaly_score = probabilities[0][1].item() if probabilities.shape[1] > 1 else probabilities[0][0].item()

        return {
            "is_anomaly": anomaly_score > 0.5, # Using a fixed threshold for the example
            "anomaly_score": anomaly_score
        }
    except Exception as e:
        logger.error(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail="An error occurred during inference.")

@app.get("/health")
def health_check():
    return {"status": "ok" if MODEL else "degraded"}