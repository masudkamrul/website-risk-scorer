import requests
import time
import csv
import os

API_URL = "http://127.0.0.1:8000/scan_url"
CSV_PATH = "data/fraudshield_dataset_v4.csv"
SAFE_URLS_FILE = "data/safe_urls_us_v4.txt"

# Load safe URLs from text file
if not os.path.exists(SAFE_URLS_FILE):
    print(f"❌ File not found: {SAFE_URLS_FILE}")
    exit()

with open(SAFE_URLS_FILE, "r", encoding="utf-8") as f:
    SAFE_SITES = [line.strip() for line in f if line.strip()]

print(f"Loaded {len(SAFE_SITES)} safe URLs")

def save_to_csv(url, result):
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            time.time(),
            url,
            *([None] * 24),  # placeholder for 24 features
            result["risk_score"],
            result["risk_class"],
            result["threat_category"],
            result["auto_label"],
            "Safe"  # VERIFIED LABEL
        ])

for i, url in enumerate(SAFE_SITES, 1):
    try:
        res = requests.post(API_URL, json={"url": url}, timeout=10)
        if res.status_code == 200:
            result = res.json()
            save_to_csv(url, result)
            print(f"[{i}/{len(SAFE_SITES)}] {url} → {result['risk_class']} ({result['risk_score']}%)")
        else:
            print(f"[{i}] ❌ HTTP {res.status_code} for {url}")
    except Exception as e:
        print(f"[{i}] ❌ Exception for {url}: {e}")

    time.sleep(1.0)  # Prevent rate limiting
