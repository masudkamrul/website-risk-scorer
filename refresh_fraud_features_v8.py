import csv
import asyncio
import aiohttp
from datetime import datetime

INPUT_FILE = "data/fraudshield_dataset_v3.csv"
OUTPUT_FILE = "data/fraudshield_dataset_v8.csv"
API_URL = "https://website-risk-scorer-api.onrender.com/scan_url"
CONCURRENCY = 3

semaphore = asyncio.Semaphore(CONCURRENCY)
results = []
failed_urls = []

async def fetch(session, url, retries=2):
    async with semaphore:
        for _ in range(retries):
            try:
                async with session.post(API_URL, json={"url": url}, timeout=15) as resp:
                    if resp.status == 200:
                        try:
                            return await resp.json()
                        except:
                            await asyncio.sleep(1)
                            continue
                    await asyncio.sleep(1)
            except:
                await asyncio.sleep(1)
        return None

async def process_urls():
    global results, failed_urls

    with open(INPUT_FILE, "r") as f:
        reader = csv.DictReader(f)
        urls = list(reader)

    total = len(urls)
    print(f"\n⚡ V8 Fraud Feature Refresh — Total URLs: {total}\n")

    async with aiohttp.ClientSession() as session:
        tasks = []
        for row in urls:
            url = row.get("url") or row.get("URL")
            tasks.append(fetch(session, url))

        responses = await asyncio.gather(*tasks)

        for idx, (row, result) in enumerate(zip(urls, responses)):
            url = row.get("url") or row.get("URL")

            if result:
                results.append({
                    "url": url,
                    "domain_age_days": result.get("domain_age_days", 0),
                    "blacklist_flag": result.get("blacklist_flag", 0),
                    "label": "fraud"
                })
            else:
                failed_urls.append(url)

            if idx % 50 == 0:
                print(f"{idx}/{total} processed…")

    if results:
        fieldnames = list(results[0].keys())
        with open(OUTPUT_FILE, "w", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

        print("\n🎯 Fraud V8 dataset created successfully!")
        print(f"Saved: {OUTPUT_FILE}")
        print(f"Successful: {len(results)}")
        print(f"Failed: {len(failed_urls)}")
    else:
        print("\n❌ API returned no valid results — check API JSON structure.")
        print("Please share one more sample output if needed.")

if __name__ == "__main__":
    asyncio.run(process_urls())
