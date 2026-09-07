import re
import numpy as np
import tldextract
from sklearn.ensemble import RandomForestClassifier

# --- AI MACHINE LEARNING MODEL IN-MEMORY TRAINING ---
# Mocking a pre-trained ML Model on Phishing Dataset (URLs & Structural Features)
X_train = np.array([
    [80, 1, 2, 1, 0, 4, 1, 0, 3],  # Phishing sample
    [95, 2, 3, 2, 1, 5, 1, 0, 4],  # Phishing sample
    [22, 0, 0, 0, 0, 1, 0, 1, 0],  # Legitimate sample
    [31, 0, 1, 0, 0, 2, 0, 1, 0],  # Legitimate sample
])
y_train = np.array([1, 1, 0, 0])  # 1 = Phishing, 0 = Safe

# Train Random Forest Classifier
ai_model = RandomForestClassifier(n_estimators=10, random_state=42)
ai_model.fit(X_train, y_train)


def extract_url_features(url: str) -> list:
    """Extracts numerical feature vector for the ML Model."""
    url_len = len(url)
    at_cnt = url.count('@')
    hyphen_cnt = url.count('-')
    question_cnt = url.count('?')
    equal_cnt = url.count('=')
    dot_cnt = url.count('.')
    
    ip_pattern = r"(([0-1]?\d{1,2}|2[0-4]\d|25[0-5])\.){3}([0-1]?\d{1,2}|2[0-4]\d|25[0-5])"
    has_ip = 1 if re.search(ip_pattern, url) else 0
    has_https = 1 if url.startswith('https') else 0
    
    extracted = tldextract.extract(url)
    subdomains = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    
    return [url_len, at_cnt, hyphen_cnt, question_cnt, equal_cnt, dot_cnt, has_ip, has_https, subdomains]


def analyze_nlp_intent(text: str) -> float:
    """NLP Semantic Analysis: Detects urgency and credential harvesting intent in text."""
    urgency_keywords = ["urgent", "verify", "account suspended", "immediate action", "login", "password reset", "unauthorized access", "bank"]
    text_lower = text.lower()
    
    matched = sum(1 for word in urgency_keywords if word in text_lower)
    # Convert matched intent score into percentage (0.0 to 1.0)
    nlp_score = min(matched / 3.0, 1.0)
    return nlp_score


def predict_ai_phishing(url: str, email_text: str = "") -> tuple:
    features = extract_url_features(url)
    
    # Layer 1: Machine Learning Model Inference
    features_array = np.array(features).reshape(1, -1)
    ml_prob = ai_model.predict_proba(features_array)[0][1] * 100
    
    # Layer 2: NLP Semantic Intent Engine
    nlp_score = 0.0
    if email_text:
        nlp_score = analyze_nlp_intent(email_text) * 100
    
    # Hybrid AI Risk Score
    final_risk_score = float(round((ml_prob * 0.7) + (nlp_score * 0.3), 2))
    
    # FIX: Cast numpy.bool_ to Python standard bool()
    is_phishing = bool(final_risk_score >= 50.0)
    
    reasons = []
    if features[6] == 1:
        reasons.append("ML Engine: Raw IP host detected instead of registered domain.")
    if features[1] > 0:
        reasons.append("ML Engine: Suspicious '@' character routing bypass.")
    if features[8] > 2:
        reasons.append(f"ML Engine: Anomaly detected with {features[8]} subdomains.")
    if nlp_score > 30:
        reasons.append("NLP Engine: High urgency & credential theft semantics detected.")
    if features[7] == 0:
        reasons.append("Security Alert: Missing SSL/HTTPS encryption.")
        
    return is_phishing, final_risk_score, reasons