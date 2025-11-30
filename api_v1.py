from data.data_logger import log_entry
from fastapi import FastAPI
from pydantic import BaseModel
from joblib import load
import requests
from datetime import datetime
import tldextract
import ssl
import socket
from urllib.parse import urlparse
import os

import pandas as pd

def domain_already_logged(url: str, csv_path: str) -> bool:
    try:
        domain = tldextract.extract(url).registered_domain
        if not os.path.exists(csv_path):
            return False
        
        df = pd.read_csv(csv_path)
        
        # Extract domain from existing URLs
        existing_domains = df['url'].apply(lambda u: tldextract.extract(u).registered_domain)
        return domain in existing_domains.values

    except Exception as e:
        print("Check logged error:", e)
        return False


CSV_PATH = "data/fraudshield_dataset_v3.csv"


app = FastAPI()
model = load("fraudshield_model_v3.joblib")

GOOGLE_SB_KEY = os.getenv("GOOGLE_SB_KEY", "")

# WHOIS API Settings (apilayer)
APILAYER_KEY = os.getenv("APILAYER_KEY", "")
WHOIS_API_URL = "https://api.apilayer.com/whois/query"

# 📁 V3 dataset path (your existing "data" folder)
CSV_PATH = os.path.join("data", "fraudshield_dataset_v3.csv")
os.makedirs("data", exist_ok=True)


class ScoreRequest(BaseModel):
    features: list
    url: str


# =============== External Signals =============== #

def check_safe_browsing(url: str) -> int:
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}"

    payload = {
        "client": {"clientId": "fraudshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        data = response.json()
        return 1 if "matches" in data else 0
    except Exception as e:
        print("[FraudShield][SafeBrowsing] Error:", e)
        return 0


def get_domain_age_days(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        if not domain:
            return 365

        headers = {"apikey": APILAYER_KEY}
        res = requests.get(
            WHOIS_API_URL,
            headers=headers,
            params={"domain": domain},
            timeout=5,
        )
        data = res.json()

        created = data.get("result", {}).get("created")
        if not created:
            return 365

        created_date = datetime.strptime(created[:10], "%Y-%m-%d")
        age_days = (datetime.utcnow() - created_date).days
        return max(age_days, 0)

    except Exception as e:
        print("[FraudShield][WHOIS] Error:", e)
        return 365


def get_security_headers(url: str) -> dict:
    try:
        resp = requests.get(url, timeout=4)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        return {
            "has_hsts_header": 1 if "strict-transport-security" in headers else 0,
            "has_csp_header": 1 if "content-security-policy" in headers else 0,
        }

    except Exception as e:
        print(f"[FraudShield][Headers] Error for {url}:", e)
        return {"has_hsts_header": 0, "has_csp_header": 0}


def get_ssl_expiry_days(url: str) -> int:
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return -1

        hostname = parsed.hostname
        port = parsed.port or 443

        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter")
        if not not_after_str:
            return -1

        expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        return max((expiry - datetime.utcnow()).days, -1)

    except Exception as e:
        print(f"[FraudShield][SSL Expiry] Error for {url}: {e}")
        return -1


# =============== Advanced Threat Mapping =============== #

def map_risk_class(risk_score: float, sb_flag: int) -> str:
    """
    Final FraudShield risk mapping with Safe Browsing hard override (SB-A):

    ≤25   → Safe
    ≤40   → Low Risk
    41-70 → Suspicious
    71-95 → High Risk
    >96 or sb_flag=1 → Blacklisted Threat
    """

    # 🔒 1) Safe Browsing hard override (SB-A)
    if sb_flag == 1 or risk_score > 96:
        return "Blacklisted Threat"

    # 🔢 2) Score-based tiers
    if risk_score <= 25:
        return "Safe"
    if risk_score <= 40:
        return "Low Risk"
    if risk_score <= 70:
        return "Suspicious"
    if risk_score <= 95:
        return "High Risk"

    # Fallback (shouldn’t really be hit)
    return "Blacklisted Threat"


def map_threat_category(
    risk_score: float,
    domain_age_days: int,
    ssl_days_to_expiry: int,
    sb_flag: int,
    uses_https: int,
    mixed_content_ratio: float,
    has_hsts_header: int,
    has_csp_header: int,
    has_hsts_meta: int,
    has_csp_meta: int,
) -> str:
    """
    Advanced hybrid logic using multiple signals.
    """
    # 1) Hard blacklists → highest priority
    if sb_flag == 1:
        return "Phishing/Malware Source"

    reasons = []

    # 2) HTTPS / SSL / transport security
    if uses_https == 0:
        reasons.append("No HTTPS Encryption")
    if ssl_days_to_expiry < 0:
        reasons.append("Expired SSL Certificate")
    elif 0 <= ssl_days_to_expiry < 15:
        reasons.append("SSL Certificate Expiring Soon")

    # 3) Mixed content (HTTPS + HTTP resources)
    if mixed_content_ratio > 0.2:
        reasons.append("Insecure Mixed Content")

    # 4) Security headers
    if not (has_hsts_header or has_hsts_meta):
        reasons.append("Missing HSTS Protection")
    if not (has_csp_header or has_csp_meta):
        reasons.append("Missing CSP Policy")

    # 5) Domain age
    if domain_age_days < 30:
        reasons.append("Very Young Domain")
    elif domain_age_days < 90:
        reasons.append("New Domain")

    # Decide main category
    if not reasons and risk_score <= 25:
        return "Safe"

    # Group into a readable umbrella category
    if "Very Young Domain" in reasons or "New Domain" in reasons:
        if risk_score > 50:
            return "New Domain Fraud Risk"
        else:
            return "Young Domain Risk"

    if "No HTTPS Encryption" in reasons or "Expired SSL Certificate" in reasons or "SSL Certificate Expiring Soon" in reasons:
        return "Weak Transport Security"

    if "Insecure Mixed Content" in reasons and risk_score > 50:
        return "Mixed Content Exploitation Risk"

    if risk_score > 75:
        return "High Fraud Likelihood"

    if risk_score > 25:
        return "Moderate Fraud Indicators"

    # Fallback
    return "Potential Fraud Indicators"


def build_auto_label(risk_class: str, threat_category: str) -> str:
    return f"{risk_class} — {threat_category}"


# =============== /score Endpoint =============== #

@app.post("/score")
def get_score(request: ScoreRequest):
    features = request.features.copy()

    # WHOIS update
    domain_age = get_domain_age_days(request.url)
    if len(features) > 0:
        features[0] = domain_age

    # Safe Browsing override
    sb_flag = check_safe_browsing(request.url)
    if len(features) > 7:
        features[7] = sb_flag

    # Server-side security
    security = get_security_headers(request.url)
    has_hsts_header = security["has_hsts_header"]
    has_csp_header = security["has_csp_header"]
    ssl_days_to_expiry = get_ssl_expiry_days(request.url)

    # Frontend signals
    uses_https = int(features[18]) if len(features) > 18 else 0
    mixed_content_ratio = float(features[21]) if len(features) > 21 else 0.0
    has_hsts_meta = int(features[22]) if len(features) > 22 else 0
    has_csp_meta = int(features[23]) if len(features) > 23 else 0

    # Model predict
    model_features = features[:20]
    prob = model.predict_proba([model_features])[0][1]
    risk_score = float(prob * 100)

    # SB-A classification
    risk_class = map_risk_class(risk_score, sb_flag)
    threat_category = map_threat_category(
        risk_score, domain_age, ssl_days_to_expiry, sb_flag,
        uses_https, mixed_content_ratio,
        has_hsts_header, has_csp_header,
        has_hsts_meta, has_csp_meta
    )
    auto_label = build_auto_label(risk_class, threat_category)

    # Force high score for blacklist
    if risk_class == "Blacklisted Threat" and risk_score < 99:
        risk_score = 99.0

    # Log
    try:
        if not domain_already_logged(request.url, CSV_PATH):
            log_entry(
                url=request.url,
                features=features,
                score=risk_score,
                risk_class=risk_class,
                threat_category=threat_category,
                auto_label=auto_label,
                csv_path=CSV_PATH,
            )
            print("📌 Logged dataset entry:", request.url)
        else:
            print("⏭️ Skipped duplicate domain:", request.url)
    except Exception as e:
        print("❌ Logging Error:", e)

    return {
        "risk_score": round(risk_score, 2),
        "risk_class": risk_class,
        "threat_category": threat_category,
        "auto_label": auto_label,
        "blacklist_flag": sb_flag,
        "domain_age_days": domain_age,
        "has_hsts_header": has_hsts_header,
        "has_csp_header": has_csp_header,
        "ssl_days_to_expiry": ssl_days_to_expiry,
    }


# =============== /scan_url Endpoint (manual URL box) =============== #

@app.post("/scan_url")
def scan_url(data: dict):
    url = data["url"]

    # Same signals as content.js + server features
    domain_age = get_domain_age_days(url)
    sb_flag = check_safe_browsing(url)
    security = get_security_headers(url)
    has_hsts_header = security["has_hsts_header"]
    has_csp_header = security["has_csp_header"]
    ssl_days_to_expiry = get_ssl_expiry_days(url)

    parsed = urlparse(url)
    https_flag = 1 if parsed.scheme == "https" else 0

    # Build full feature vector
    features = [0] * 24
    features[0] = domain_age
    features[7] = sb_flag
    features[18] = https_flag
    features[22] = has_hsts_header
    features[23] = has_csp_header

    # Predict
    model_features = features[:20]
    prob = model.predict_proba([model_features])[0][1]
    risk_score = float(prob * 100)

    risk_class = map_risk_class(risk_score, sb_flag)
    threat_category = "Manual Scan Risk Analysis"
    auto_label = build_auto_label(risk_class, threat_category)

    # Same blacklist override
    if risk_class == "Blacklisted Threat" and risk_score < 99:
        risk_score = 99.0

    # Log if new
    try:
        if not domain_already_logged(url, CSV_PATH):
            log_entry(
                url=url,
                features=features,
                score=risk_score,
                risk_class=risk_class,
                threat_category=threat_category,
                auto_label=auto_label,
                csv_path=CSV_PATH,
            )
            print("📌 Logged MANUAL:", url)
        else:
            print("⏭️ Skipped duplicate MANUAL domain:", url)
    except Exception as e:
        print("❌ Manual Logging Error:", e)

    return {
        "risk_score": round(risk_score, 2),
        "risk_class": risk_class,
        "threat_category": threat_category,
        "auto_label": auto_label,
        "blacklist_flag": sb_flag,
        "domain_age_days": domain_age,
        "has_hsts_header": has_hsts_header,
        "has_csp_header": has_csp_header,
        "ssl_days_to_expiry": ssl_days_to_expiry,
    }

