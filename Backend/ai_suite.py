import pymupdf  # PyMuPDF
import numpy as np
import re
import math
import os
import sys
from difflib import SequenceMatcher

# Path Fix for Root Packages
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sklearn.ensemble import RandomForestClassifier
from transformers import pipeline
from Backend.database import log_scan

# -------------------------------------------------------------
# BRAND PROTECTION & TYPOSQUATTING DICTIONARY
# -------------------------------------------------------------
PROTECTED_BRANDS = {
    "facebook": ["facebook.com", "fb.com"],
    "google": ["google.com"],
    "instagram": ["instagram.com"],
    "microsoft": ["microsoft.com", "office.com"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "apple": ["apple.com"],
    "github": ["github.com"],
    "youtube": ["youtube.com"],
    "amazon": ["amazon.com"]
}

TRUSTED_EXACT_DOMAINS = [
    "facebook.com", "www.facebook.com",
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "github.com", "www.github.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "wikipedia.org", "www.wikipedia.org",
    "linkedin.com", "www.linkedin.com"
]

# -------------------------------------------------------------
# 1. DYNAMIC URL & DOM ML SCANNER
# -------------------------------------------------------------
X_train_urls = np.array([
    [2.1, 15, 1, 0, 0],
    [3.4, 22, 2, 0, 0],
    [6.8, 85, 4, 3, 1],
    [7.5, 95, 5, 4, 1],
    [2.8, 18, 1, 0, 0],
    [8.1, 110, 6, 5, 1]
])
y_train_urls = np.array([0, 0, 1, 1, 0, 1])

url_ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
url_ml_model.fit(X_train_urls, y_train_urls)

def calculate_string_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0
    for x in set(text):
        p_x = text.count(x) / len(text)
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def extract_url_dynamic_features(url: str):
    entropy = calculate_string_entropy(url)
    length = len(url)
    subdomains = len(url.split('.')) - 1
    keywords = ['login', 'verify', 'update', 'account', 'secure', 'banking', 'free', 'bonus', 'wallet', 'crypto']
    suspicious_count = sum(1 for word in keywords if word in url.lower())
    has_ip_or_at = 1 if (re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) or '@' in url) else 0
    return np.array([[entropy, length, subdomains, suspicious_count, has_ip_or_at]])

def check_typosquatting(hostname: str) -> bool:
    # BUG FIX: Remove 'www.' before checking so 'facebo0k' is checked, not 'www'
    clean_hostname = hostname[4:] if hostname.startswith("www.") else hostname
    
    # Extract main body and replace homograph characters (0->o, 1->l, etc)
    domain_body = clean_hostname.split('.')[0].replace('0', 'o').replace('1', 'l').replace('3', 'e')
    
    for brand, official_domains in PROTECTED_BRANDS.items():
        similarity = SequenceMatcher(None, domain_body, brand).ratio()
        if similarity > 0.75 and not any(hostname.endswith(off) for off in official_domains):
            return True
    return False

def analyze_url_dynamic(url: str, html_content: str = "", has_password_field: bool = False, has_credit_card_field: bool = False) -> dict:
    url_lower = url.lower().strip()
    
    domain_match = re.search(r'https?://([^/:]+)', url_lower)
    hostname = domain_match.group(1) if domain_match else url_lower.split('/')[0]

    # 1. Whitelist Check
    is_whitelisted = any(hostname == domain or hostname.endswith("." + domain) for domain in TRUSTED_EXACT_DOMAINS)

    if is_whitelisted and not (has_password_field and not url_lower.startswith('https')):
        final_score = 4.5
        threat_level = "SECURE (LOW RISK)"
        is_threat = False
        log_scan("URL", url, final_score, is_threat, "AlphaShield Whitelist Core", "Verified Enterprise Domain")
        return {
            "url": url,
            "risk_score": final_score,
            "is_threat": is_threat,
            "is_phishing": is_threat,
            "engine": "AlphaShield Whitelist Core",
            "threat_level": threat_level
        }

    # 2. Typosquatting / Homograph Check
    if check_typosquatting(hostname):
        final_score = 95.5
        threat_level = "CRITICAL THREAT (TYPOSQUATTING PHISHING)"
        is_threat = True
        log_scan("URL", url, final_score, is_threat, "AlphaShield Typosquatting Detector", "Brand Impersonation Flagged")
        return {
            "url": url,
            "risk_score": final_score,
            "is_threat": is_threat,
            "is_phishing": is_threat,
            "engine": "AlphaShield Brand Protection Core",
            "threat_level": threat_level
        }

    # 3. Dynamic ML Check
    features = extract_url_dynamic_features(url)
    raw_ml_prob = float(url_ml_model.predict_proba(features)[0][1] * 100)

    if has_password_field and not url.startswith('https'):
        raw_ml_prob += 45.0
    elif has_password_field and any(brand in url_lower for brand in ['login', 'verify', 'account', 'bank', 'secure']):
        raw_ml_prob += 35.0
        
    if has_credit_card_field:
        raw_ml_prob += 40.0
        
    if html_content:
        if 'eval(' in html_content or 'unescape(' in html_content:
            raw_ml_prob += 25.0
        if '<iframe' in html_content and ('visibility:hidden' in html_content or 'display:none' in html_content):
            raw_ml_prob += 30.0

    final_score = float(round(min(max(raw_ml_prob, 5.0), 99.9), 2))
    
    if final_score >= 65.0:
        threat_level = "CRITICAL THREAT (MALICIOUS)"
        is_threat = True
    elif final_score >= 30.0:
        threat_level = "MODERATE RISK (SUSPICIOUS)"
        is_threat = True
    else:
        threat_level = "SECURE (LOW RISK)"
        is_threat = False

    log_scan("URL", url, final_score, is_threat, "AlphaShield Dynamic DOM+ML Engine", f"Risk: {final_score}%")

    return {
        "url": url,
        "risk_score": final_score,
        "is_threat": is_threat,
        "is_phishing": is_threat,
        "engine": "AlphaShield Multi-Vector Core",
        "threat_level": threat_level
    }

# -------------------------------------------------------------
# 2. PURE ML MODEL FOR PDF MALWARE DETECTION
# -------------------------------------------------------------
X_train_pdf = np.array([
    [2.1, 0, 1, 0, 0],
    [3.5, 0, 2, 0, 0],
    [7.8, 3, 12, 1, 1],
    [6.9, 1, 8, 2, 1],
    [1.8, 0, 0, 0, 0],
    [8.2, 5, 15, 3, 1]
])
y_train_pdf = np.array([0, 0, 1, 1, 0, 1])

pdf_ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
pdf_ml_model.fit(X_train_pdf, y_train_pdf)

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * np.log2(p_x)
    return round(float(entropy), 2)

def scan_pdf_file_pure_ai(file_bytes: bytes, filename: str) -> dict:
    doc = pymupdf.open(stream=file_bytes, filetype="pdf")
    entropy_score = calculate_entropy(file_bytes)
    
    js_count = 0
    for i in range(1, doc.xref_length()):
        try:
            xref_data = doc.xref_object(i)
            if "/JS" in xref_data or "/JavaScript" in xref_data:
                js_count += 1
        except Exception:
            pass
            
    extracted_urls = []
    suspicious_ip_urls = 0
    for page in doc:
        for link in page.get_links():
            if "uri" in link:
                uri = link["uri"]
                extracted_urls.append(uri)
                if "@" in uri or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', uri):
                    suspicious_ip_urls += 1

    open_action_count = 1 if "/OpenAction" in str(doc.pdf_catalog()) else 0

    feature_vector = np.array([[entropy_score, js_count, len(extracted_urls), suspicious_ip_urls, open_action_count]])
    ai_prob = float(pdf_ml_model.predict_proba(feature_vector)[0][1] * 100)
    ai_risk_score = float(round(ai_prob, 2))
    
    if ai_risk_score >= 65.0:
        threat_level = "CRITICAL MALICIOUS PDF"
        is_threat = True
    elif ai_risk_score >= 30.0:
        threat_level = "MODERATE SUSPICIOUS PDF"
        is_threat = True
    else:
        threat_level = "SECURE CLEAN DOCUMENT"
        is_threat = False

    log_scan("PDF", filename, ai_risk_score, is_threat, "RandomForest PDF Structural ML Model", f"Entropy: {entropy_score}")

    return {
        "filename": filename,
        "risk_score": ai_risk_score,
        "is_threat": is_threat,
        "urls_found": extracted_urls,
        "engine": "RandomForest Classifier (Structural ML)",
        "threat_level": threat_level
    }

# -------------------------------------------------------------
# 3. PURE DEEP LEARNING MODEL FOR EMAIL TEXT INTENT
# -------------------------------------------------------------
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
try:
    nlp_classifier = pipeline("zero-shot-classification", model="typeform/distilbert-base-uncased-mnli")
except Exception:
    nlp_classifier = pipeline("zero-shot-classification")

def analyze_email_pure_ai(text: str) -> dict:
    candidate_labels = ["phishing scam urgency credential theft", "legitimate neutral communication"]
    result = nlp_classifier(text, candidate_labels)
    
    raw_ai_score = float(result['scores'][result['labels'].index("phishing scam urgency credential theft")] * 100)
    ai_risk_score = float(round(raw_ai_score, 2))
    is_threat = bool(ai_risk_score >= 50.0)
    
    log_scan("EMAIL", text[:40] + "...", ai_risk_score, is_threat, "DistilBERT Neural Transformer", f"Top Intent: {result['labels'][0]}")
    
    return {
        "risk_score": ai_risk_score,
        "is_threat": is_threat,
        "engine": "DistilBERT Transformer Neural Engine",
        "neural_intent_label": result['labels'][0]
    }