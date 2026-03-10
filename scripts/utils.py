"""
Shared utilities for data fetching and processing.
"""
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from .config import DATA_DIR, REQUEST_HEADERS, REQUEST_TIMEOUT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cyber-landscape")


# Browser-like User-Agent for sites that block bot traffic (e.g. .gov.au)
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def fetch_url(url: str, headers: dict = None, params: dict = None,
              method: str = "GET", json_body: dict = None,
              retries: int = 3, backoff: float = 2.0,
              timeout: int = None) -> requests.Response | None:
    """Fetch a URL with retries and exponential backoff."""
    merged_headers = {**REQUEST_HEADERS, **(headers or {})}

    # .gov.au sites block bot User-Agents from cloud IPs;
    # use a browser UA and only retry once (let the feedparser fallback handle it)
    is_gov_au = ".gov.au" in url
    if is_gov_au:
        merged_headers["User-Agent"] = _BROWSER_UA
        merged_headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        merged_headers["Accept-Language"] = "en-AU,en;q=0.9"
        if timeout is None:
            timeout = 60
        retries = min(retries, 1)  # fail fast, let feedparser fallback try
    elif timeout is None:
        if ".gov." in url:
            timeout = 90
        else:
            timeout = REQUEST_TIMEOUT

    for attempt in range(retries):
        try:
            if method.upper() == "POST":
                resp = requests.post(
                    url, headers=merged_headers, json=json_body,
                    params=params, timeout=timeout
                )
            else:
                resp = requests.get(
                    url, headers=merged_headers, params=params,
                    timeout=timeout
                )
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            logger.warning(f"Attempt {attempt + 1}/{retries} failed for {url}: {e}")
            if attempt < retries - 1:
                time.sleep(backoff ** attempt)

    logger.error(f"All {retries} attempts failed for {url}")
    return None


def save_data(filename: str, data: dict | list) -> Path:
    """Save data as JSON to the data directory."""
    filepath = DATA_DIR / filename
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    logger.info(f"Saved {filepath} ({filepath.stat().st_size:,} bytes)")
    return filepath


def load_data(filename: str) -> dict | list | None:
    """Load data from a JSON file in the data directory."""
    filepath = DATA_DIR / filename
    if not filepath.exists():
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def now_iso() -> str:
    """Return current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def parse_date(date_str: str) -> datetime | None:
    """Try parsing a date string in common formats."""
    from dateutil import parser as dateparser
    try:
        return dateparser.parse(date_str)
    except (ValueError, TypeError):
        return None


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text to max_length with ellipsis."""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."
