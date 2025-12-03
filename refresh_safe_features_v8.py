import csv
import asyncio
import aiohttp
from datetime import datetime

INPUT_FILE = "data/safe_urls_us_v6.txt"
OUTPUT_FILE = "data/safe_dataset_v8.csv"
API_URL = "https://website-risk-scorer-api.onrender.com/scan_url"
CONCURRENCY = 3  # be gentle with Render

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

    # read URLs from txt file (one per line)
    with open(INPUT_FILE, "r") as f:
        urls = [line.strip() for line in f.readlines() if line.strip()]

    total = len(urls)
    print(f"\n🟢 Refreshing SAFE dataset — Total URLs: {total}\n")

    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in urls]
        responses = await asyncio.gather(*tasks)

        for idx, (url, result) in enumerate(zip(urls, responses)):

            if result:
                results.append({
                    "url": url,
                    "domain_age_days": result.get("domain_age_days", 0),
                    "blacklist_flag": result.get("blacklist_flag", 0),
                    "label": "safe"
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

        print("\n🟢 SAFE V8 dataset created successfully!")
        print(f"Saved: {OUTPUT_FILE}")
        print(f"Successful: {len(results)}")
        print(f"Failed: {len(failed_urls)}")
    else:
        print("\n❌ No valid results returned — check API structure.")

if __name__ == "__main__":
    asyncio.run(process_urls())
