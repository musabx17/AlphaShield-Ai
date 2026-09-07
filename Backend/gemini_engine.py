import os
import json
from pydantic import BaseModel, Field
from google import genai

# Define Pydantic schema for strict JSON response enforcement
class ThreatAnalysisResponse(BaseModel):
    gemini_risk_score: float = Field(description="Risk score between 0.0 and 100.0")
    is_threat: bool = Field(description="True if threat detected, False otherwise")
    attack_vector: str = Field(description="Category of the attack vector")
    ai_reasoning: str = Field(description="Summary of analysis findings")


def get_gemini_client():
    # Use standard uppercase convention for environment variables
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("Gemini_API_KEY")
    if not api_key:
        return None
    return genai.Client(api_key=api_key)


def deep_scan_with_gemini(target_type: str, content: str, target_name: str) -> dict:
    """
    Performs deep AI threat analysis using Gemini 2.0 Flash.
    """
    client = get_gemini_client()
    if not client:
        return {
            "gemini_active": False,
            "risk_score": 0.0,
            "reasoning": "GEMINI_API_KEY environment variable not set."
        }

    prompt = f"""
    You are an enterprise AI Cybersecurity Threat Analyst.
    Perform deep security analysis on the following {target_type}.

    Target Name/URL: {target_name}
    
    Content/DOM Snippet:
    {content[:3000]}

    Evaluate for:
    1. Brand Impersonation & Social Engineering.
    2. Obfuscated Scripts, Hidden Input Harvesting, or Credential Theft.
    3. Malicious Redirection Patterns.
    
    Respond ONLY with valid JSON matching this schema:
    {{
        "gemini_risk_score": <float 0-100>,
        "is_threat": <boolean>,
        "attack_vector": "<string>",
        "ai_reasoning": "<string>"
    }}
    """

    try:
        # Use the new google-genai Client API with updated model
        response = client.models.generate_content(
            model='models/gemini-3.6-flash',
            contents=prompt
        )
        
        # Parse the response text as JSON
        response_text = response.text.strip()
        
        # Clean up markdown formatting if present
        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.startswith('```'):
            response_text = response_text[3:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
            
        response_json = json.loads(response_text.strip())
        
        # Validate against schema
        data = ThreatAnalysisResponse(**response_json)
        return {
            "gemini_active": True,
            "risk_score": data.gemini_risk_score,
            "is_threat": data.is_threat,
            "attack_vector": data.attack_vector,
            "ai_reasoning": data.ai_reasoning
        }
    except Exception as e:
        return {
            "gemini_active": False,
            "risk_score": 0.0,
            "reasoning": f"Gemini API Execution Error: {str(e)}"
        }