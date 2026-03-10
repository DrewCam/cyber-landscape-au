"""
Refresh the ACSC feed cache from your local machine.

cyber.gov.au is behind Cloudflare bot protection which blocks all automated
HTTP clients. This script uses Selenium with Microsoft Edge (pre-installed
on Windows 10/11) to fetch the RSS feeds through a real browser engine.

Usage:
    pip install selenium webdriver-manager feedparser
    python -m scripts.refresh_acsc
"""
import json
import sys
import time
import feedparser
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
CACHE_DIR = PROJECT_ROOT / "data" / "cache"
CACHE_FILE = CACHE_DIR / "acsc_feeds.json"

ACSC_FEEDS = {
    "ACSC Alerts": "https://www.cyber.gov.au/rss/alerts",
    "ACSC Advisories": "https://www.cyber.gov.au/rss/advisories",
    "ACSC News": "https://www.cyber.gov.au/rss/news",
    "ACSC Publications": "https://www.cyber.gov.au/rss/publications",
    "ACSC Threats": "https://www.cyber.gov.au/rss/threats",
}


def get_driver():
    """Set up a Selenium WebDriver, trying Edge first (always on Windows)."""
    try:
        from selenium import webdriver
    except ImportError:
        print("ERROR: selenium is required. Run: pip install selenium webdriver-manager")
        sys.exit(1)

    # Try Edge first (guaranteed on Windows 10/11)
    try:
        from selenium.webdriver.edge.options import Options as EdgeOptions
        from selenium.webdriver.edge.service import Service as EdgeService
        from webdriver_manager.microsoft import EdgeChromiumDriverManager

        print("  Setting up Microsoft Edge (headless)...")
        options = EdgeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")

        service = EdgeService(EdgeChromiumDriverManager().install())
        driver = webdriver.Edge(service=service, options=options)
        print("  Edge ready.")
        return driver
    except Exception as e:
        print(f"  Edge failed: {e}")

    # Fallback to Chrome
    try:
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        from selenium.webdriver.chrome.service import Service as ChromeService
        from webdriver_manager.chrome import ChromeDriverManager

        print("  Trying Chrome instead...")
        options = ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")

        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        print("  Chrome ready.")
        return driver
    except Exception as e:
        print(f"  Chrome also failed: {e}")

    print("  ERROR: No browser available. Install Chrome or ensure Edge is up to date.")
    return None


def fetch_feeds(driver):
    """Fetch all ACSC feeds using the browser driver."""
    entries = []

    for feed_name, feed_url in ACSC_FEEDS.items():
        print(f"  Fetching {feed_name}...")
        try:
            driver.get(feed_url)
            # Wait for Cloudflare challenge to clear
            time.sleep(5)

            # Get page source (should be RSS XML after challenge passes)
            page_source = driver.page_source

            # Check if we got a challenge page instead of RSS
            if "challenge" in page_source.lower()[:2000] or "<item>" not in page_source.lower():
                print(f"    Challenge detected, waiting longer...")
                time.sleep(10)
                page_source = driver.page_source

            feed = feedparser.parse(page_source)

            if feed.entries:
                for entry in feed.entries[:50]:
                    published = ""
                    if hasattr(entry, "published"):
                        published = entry.published
                    elif hasattr(entry, "updated"):
                        published = entry.updated

                    summary = entry.get("summary", "")
                    if len(summary) > 300:
                        summary = summary[:297] + "..."

                    entries.append({
                        "title": entry.get("title", "Untitled"),
                        "link": entry.get("link", ""),
                        "published": published,
                        "summary": summary,
                        "source": feed_name,
                    })
                print(f"    {len(feed.entries)} entries")
            else:
                print(f"    WARNING: no entries found")
        except Exception as e:
            print(f"    ERROR: {e}")

    return entries


def main():
    print("=" * 60)
    print("ACSC Feed Cache Refresh")
    print("=" * 60)
    print(f"Cache file: {CACHE_FILE}")
    print()

    driver = get_driver()
    if not driver:
        sys.exit(1)

    try:
        entries = fetch_feeds(driver)
    finally:
        driver.quit()

    if not entries:
        print("\nNo entries fetched. cyber.gov.au may be down or Cloudflare is blocking headless browsers.")
        print("You can also manually save the RSS XML from your browser and place it in the cache.")
        sys.exit(1)

    # Save cache
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = {
        "cached_at": datetime.utcnow().isoformat() + "Z",
        "entry_count": len(entries),
        "entries": entries,
    }
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

    print(f"\nCached {len(entries)} total entries to {CACHE_FILE}")
    print("\nCommit and push to update CI builds:")
    print(f"  git add {CACHE_FILE.relative_to(PROJECT_ROOT)}")
    print('  git commit -m "Update ACSC feed cache"')
    print("  git push")


if __name__ == "__main__":
    main()
