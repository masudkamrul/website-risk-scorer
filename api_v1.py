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
        existing_domains = df['url'].apply(lambda u: tldextract.extract(u).registered_domain)
        return domain in existing_domains.values
    except Exception as e:
        print("Check logged error:", e)
        return False

CSV_PATH = "data/fraudshield_dataset_v3.csv"

app = FastAPI()

# 🔥 Load V2 stable model first — before CORS / middleware
model_data = load("fraudshield_model_v7.joblib")
model = model_data["model"]

from fastapi.middleware.cors import CORSMiddleware

origins = [
    "*",  # allow Chrome extension + any website for now
    "chrome-extension://*",  # explicit extension support
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],   # allow all methods e.g. POST, OPTIONS
    allow_headers=["*"],   # allow user-agent, content-type, etc.
    expose_headers=["*"],
)

GOOGLE_SB_KEY = os.getenv("GOOGLE_SB_KEY", "")
APILAYER_KEY = os.getenv("APILAYER_KEY", "")
WHOIS_API_URL = "https://api.apilayer.com/whois/query"

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
            return 5000

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
            return 5000  # Treat unknown as very old and SAFE

        created_date = datetime.strptime(created[:10], "%Y-%m-%d")
        age_days = (datetime.utcnow() - created_date).days
        return max(age_days, 0)

    except Exception as e:
        print("[FraudShield][WHOIS] Error:", e)
        return 5000


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
    url = request.url
    features = request.features.copy()

    # Extract signals
    domain_age = get_domain_age_days(url)
    uses_https = int(features[18]) if len(features) > 18 else 1
    has_hsts_meta = int(features[22]) if len(features) > 22 else 0
    has_csp_meta = int(features[23]) if len(features) > 23 else 0
    mixed_ratio = float(features[21]) if len(features) > 21 else 0.0
    sb_flag = check_safe_browsing(url)

    # Model V5 input (exact shape 6)
    model_features = [
        domain_age,
        uses_https,
        mixed_ratio,
        has_hsts_meta,
        has_csp_meta,
        sb_flag
    ]

    prob = model.predict_proba([model_features])[0][1]
    risk_score = prob * 100

    # Safe adjustments
    if domain_age > 3650:
        risk_score *= 0.25
    if uses_https == 1:
        risk_score *= 0.35
    if has_hsts_meta or has_csp_meta:
        risk_score *= 0.45

    risk_score = max(risk_score, 0.01)

    # Classification
    if sb_flag:
        risk_class = "Blacklisted Threat"
        risk_score = 99
    elif risk_score < 10:
        risk_class = "Safe"
    elif risk_score < 40:
        risk_class = "Low Risk"
    elif risk_score < 70:
        risk_class = "Suspicious"
    else:
        risk_class = "High Risk"

    return {
        "risk_score": round(risk_score, 2),
        "risk_class": risk_class,
        "domain_age_days": domain_age,
        "uses_https": uses_https,
        "has_hsts_meta": has_hsts_meta,
        "has_csp_meta": has_csp_meta,
        "blacklist_flag": sb_flag
    }


# =============== /scan_url Endpoint =============== #

@app.post("/scan_url")
def scan_url(data: dict):
    url = data["url"]

    # Feature 1: Domain age
    domain_age_days = get_domain_age_days(url)

    # Feature 2: HTTPS flag
    parsed = urlparse(url)
    https_flag = 1 if parsed.scheme == "https" else 0

    # Check page security headers
    try:
        response = requests.get(url, timeout=8)
        headers = response.headers

        # Feature 3: HSTS presence indicator
        hsts = 1 if 'strict-transport-security' in headers else 0

        # Feature 4: CSP presence indicator
        csp = 1 if 'content-security-policy' in headers else 0

    except Exception:
        # If cannot request the site → assume unsafe headers
        hsts = 0
        csp = 0

    # Feature 5: Blacklist via Safe Browsing API
    blacklist_flag = check_safe_browsing(url)

    # NEW FEATURE VECTOR using 5 valid ML inputs
    model_features = [
        domain_age_days,
        https_flag,
        csp,
        hsts,
        blacklist_flag
    ]

    # ML scoring
    prob = model.predict_proba([model_features])[0][1]
    risk_score = prob * 100

    # Basic safety score calibrations
    if domain_age_days > 3650:
        risk_score *= 0.25
    if https_flag == 1:
        risk_score *= 0.35

    # Ensure minimal score
    risk_score = max(risk_score, 0.01)

    # Risk classification
    if blacklist_flag:
        risk_class = "Blacklisted Threat"
        risk_score = 99
    elif risk_score < 10:
        risk_class = "Safe"
    elif risk_score < 40:
        risk_class = "Low Risk"
    elif risk_score < 70:
        risk_class = "Suspicious"
    else:
        risk_class = "High Risk"

    return {
        "domain_age_days": domain_age_days,
        "https_flag": https_flag,
        "csp": csp,
        "hsts": hsts,
        "blacklist_flag": blacklist_flag,
        "risk_score": round(risk_score, 2),
        "risk_class": risk_class
    }
