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


def fetch_url(url: str, headers: dict = None, params: dict = None,
              method: str = "GET", json_body: dict = None,
              retries: int = 3, backoff: float = 2.0) -> requests.Response | None:
    """Fetch a URL with retries and exponential backoff."""
    merged_headers = {**REQUEST_HEADERS, **(headers or {})}

    for attempt in range(retries):
        try:
            if method.upper() == "POST":
                resp = requests.post(
                    url, headers=merged_headers, json=json_body,
                    params=params, timeout=REQUEST_TIMEOUT
                )
            else:
                resp = requests.get(
                    url, headers=merged_headers, params=params,
                    timeout=REQUEST_TIMEOUT
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
