import requests
import time
import csv
import os

API_URL = "http://127.0.0.1:8000/scan_url"  # Local test mode
CSV_PATH = "data/fraudshield_dataset_v4.csv"
SAFE_URLS_FILE = "data/safe_urls_us_v4.txt"

# Load safe URLs
if not os.path.exists(SAFE_URLS_FILE):
    print(f"❌ File not found: {SAFE_URLS_FILE}")
    exit()

with open(SAFE_URLS_FILE, "r", encoding="utf-8") as f:
    SAFE_SITES = [line.strip() for line in f if line.strip()]

print(f"Loaded {len(SAFE_SITES)} safe URLs")

# Ensure CSV header exists
if not os.path.exists(CSV_PATH):
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "url",
            *[f"f{i}" for i in range(24)],
            "risk_score", "risk_class",
            "threat_category", "auto_label",
            "verified_label"
        ])

# Save row to CSV
def save_to_csv(url, data):
    risk_score = data.get("risk_score", 50)
    risk_class = data.get("risk_class", "Low Risk")
    threat_category = data.get("threat_category", "Trusted Safe Domain")
    auto_label = data.get("auto_label", f"{risk_class} — {threat_category}")

    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            time.time(),
            url,
            *([0] * 24),  # placeholder features
            risk_score,
            risk_class,
            threat_category,
            auto_label,
            "Safe"
        ])

# Main loop
for i, url in enumerate(SAFE_SITES, 1):
    try:
        r = requests.post(API_URL, json={"url": url}, timeout=10)
        if r.status_code == 200:
            result = r.json()
            save_to_csv(url, result)
            print(f"[{i}/{len(SAFE_SITES)}] {url} → {result.get('risk_class')} ({result.get('risk_score')}%)")
        else:
            print(f"[{i}] ❌ HTTP {r.status_code} for {url}")
    except Exception as e:
        print(f"[{i}] ❌ Exception for {url}: {e}")

    time.sleep(1.0)
