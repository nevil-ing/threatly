from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

model_name = "mistralai/Mistral-7B-Instruct-v0.2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)
model = model.to("cuda" if torch.cuda.is_available() else "cpu")

def analyze_compliance(input_text: str, compliance_type: str = "General") -> tuple[str, bool]:
    prompt = f"""Review this data for {compliance_type} compliance violations. 
Explain clearly if there is a policy violation and why.

Input:
{input_text}

Summary:"""

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    outputs = model.generate(
        **inputs,
        max_new_tokens=256,
        temperature=0.4,
        top_p=0.75
    )

    summary = tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)
    is_violation = "violation" in summary.lower() or "non-compliant" in summary.lower()
    return summary.strip(), is_violation
