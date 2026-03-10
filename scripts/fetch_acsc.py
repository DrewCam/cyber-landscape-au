"""
Fetch advisories, alerts, news, publications, and threats from ASD/ACSC,
Five Eyes partner CERTs (CCCS, NCSC UK), CISA, and CISA ICS-CERT RSS feeds.

cyber.gov.au blocks ALL cloud/datacenter IPs (including proxies and RSS services).
ACSC feeds are fetched via one of three strategies:

1. ACSC_FEED_URL env var: a Feeder.co (or similar) JSON export URL that
   re-publishes the ACSC feeds from non-cloud infrastructure.
2. Direct fetch: works from residential/corporate IPs (local dev).
3. Cache fallback: data/cache/acsc_feeds.json committed to the repo,
   refreshed locally via `python -m scripts.refresh_acsc`.
"""
import json
import feedparser
from datetime import datetime, timezone
from pathlib import Path

from .config import SOURCES, PROJECT_ROOT, ACSC_FEED_URL
from .utils import logger, save_data, fetch_url, truncate


ACSC_CACHE_FILE = PROJECT_ROOT / "data" / "cache" / "acsc_feeds.json"


def _fetch_via_feed_url() -> list[dict]:
    """Fetch ACSC data from an external feed aggregator (e.g. Feeder.co).

    Expects the URL to return JSON with an 'items' array (JSON Feed format)
    or an RSS/Atom feed. This bypasses cyber.gov.au Cloudflare blocking
    because the aggregator fetches from its own (non-cloud) infrastructure.
    """
    if not ACSC_FEED_URL:
        return []

    logger.info(f"  Trying ACSC feed aggregator: {ACSC_FEED_URL[:60]}...")
    resp = fetch_url(ACSC_FEED_URL, timeout=30)
    if not resp:
        logger.warning("  Feed aggregator URL failed")
        return []

    entries = []
    try:
        # Try JSON Feed format first (Feeder.co exports this)
        if "json" in resp.headers.get("content-type", "").lower() or ACSC_FEED_URL.endswith(".json"):
            data = resp.json()
            items = data.get("items", [])
            for item in items[:100]:
                entries.append({
                    "title": item.get("title", "Untitled"),
                    "link": item.get("url", item.get("link", "")),
                    "published": item.get("date_published", item.get("date_modified", "")),
                    "summary": truncate(
                        item.get("summary", item.get("content_text", "")), 300
                    ),
                    "source": item.get("_source", {}).get("title", "ACSC")
                        if isinstance(item.get("_source"), dict)
                        else "ACSC",
                })
            logger.info(f"  Feed aggregator: {len(entries)} entries (JSON)")
        else:
            # Fall back to RSS/Atom parsing
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:100]:
                published = ""
                if hasattr(entry, "published"):
                    published = entry.published
                elif hasattr(entry, "updated"):
                    published = entry.updated
                entries.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "published": published,
                    "summary": truncate(entry.get("summary", ""), 300),
                    "source": "ACSC",
                })
            logger.info(f"  Feed aggregator: {len(entries)} entries (RSS)")
    except Exception as e:
        logger.error(f"  Error parsing feed aggregator response: {e}")

    return entries


def _fetch_direct(feed_url: str, feed_name: str) -> list[dict]:
    """Fetch an RSS feed directly. Works locally, fails in CI."""
    entries = []
    try:
        resp = fetch_url(feed_url, timeout=30, retries=1)
        if resp and resp.content:
            feed = feedparser.parse(resp.content)
            if feed.entries:
                for entry in feed.entries[:50]:
                    published = ""
                    if hasattr(entry, "published"):
                        published = entry.published
                    elif hasattr(entry, "updated"):
                        published = entry.updated
                    entries.append({
                        "title": entry.get("title", "Untitled"),
                        "link": entry.get("link", ""),
                        "published": published,
                        "summary": truncate(entry.get("summary", ""), 300),
                        "source": feed_name,
                    })
                logger.info(f"  {feed_name}: {len(feed.entries)} entries (live)")
    except Exception:
        pass
    return entries


def _load_acsc_cache() -> list[dict]:
    """Load cached ACSC feed data from repo."""
    if not ACSC_CACHE_FILE.exists():
        logger.warning("  No ACSC cache file found.")
        logger.warning("  Run 'python -m scripts.refresh_acsc' locally to seed it.")
        return []
    try:
        with open(ACSC_CACHE_FILE, "r", encoding="utf-8") as f:
            cache = json.load(f)
        entries = cache.get("entries", [])
        cached_at = cache.get("cached_at", "unknown")
        logger.info(f"  Loaded {len(entries)} ACSC entries from cache (fetched {cached_at})")
        return entries
    except Exception as e:
        logger.error(f"  Error loading ACSC cache: {e}")
        return []


def _save_acsc_cache(entries: list[dict]):
    """Save ACSC feed data to the cache file."""
    ACSC_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    cache = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "entry_count": len(entries),
        "entries": entries,
    }
    with open(ACSC_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)
    logger.info(f"  Saved {len(entries)} ACSC entries to cache")


def fetch_acsc_feeds() -> list[dict]:
    """Fetch ACSC feeds using a three-tier strategy:

    1. External feed aggregator (ACSC_FEED_URL env var, e.g. Feeder.co)
    2. Direct fetch (works from residential/corporate IPs only)
    3. Committed cache fallback (data/cache/acsc_feeds.json)

    cyber.gov.au blocks all cloud/datacenter IPs, so tier 1 or 3
    is needed for CI builds. Tier 2 works for local development.
    """
    logger.info("Fetching ACSC feeds...")

    # Tier 1: External feed aggregator (bypasses Cloudflare)
    if ACSC_FEED_URL:
        entries = _fetch_via_feed_url()
        if entries:
            _save_acsc_cache(entries)
            return entries
        logger.warning("  Feed aggregator failed, trying direct...")

    # Tier 2: Direct fetch (only works from residential/corporate IPs)
    all_entries = []
    for feed_name, feed_key in [
        ("ACSC Alerts", "acsc_alerts_rss"),
        ("ACSC Advisories", "acsc_advisories_rss"),
        ("ACSC News", "acsc_news_rss"),
        ("ACSC Publications", "acsc_publications_rss"),
        ("ACSC Threats", "acsc_threats_rss"),
    ]:
        feed_url = SOURCES[feed_key]
        entries = _fetch_direct(feed_url, feed_name)
        if not entries:
            logger.warning(f"  {feed_name}: live fetch failed")
            # If any single feed fails, assume we're in CI and skip the rest
            logger.info("  Detected cloud environment, switching to cache...")
            break
        all_entries.extend(entries)
    else:
        # All 5 feeds succeeded (local run): update the cache
        if all_entries:
            _save_acsc_cache(all_entries)
            return all_entries

    # Tier 3: Committed cache fallback
    return _load_acsc_cache()


def fetch_cccs_advisories() -> list[dict]:
    """Fetch Canadian Centre for Cyber Security advisories via Atom feed.

    CCCS (Canada) is a Five Eyes partner with a publicly accessible Atom feed.
    Replaces AusCERT which requires member-only access.
    """
    logger.info("Fetching CCCS (Canada) advisories...")
    entries = []

    try:
        resp = fetch_url(SOURCES["cccs_advisories"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:50]:
                published = ""
                if hasattr(entry, "published"):
                    published = entry.published
                elif hasattr(entry, "updated"):
                    published = entry.updated

                entries.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "published": published,
                    "summary": truncate(entry.get("summary", ""), 300),
                    "source": "CCCS",
                })
            logger.info(f"  CCCS: {len(feed.entries)} entries")
    except Exception as e:
        logger.error(f"Error fetching CCCS: {e}")

    return entries


def fetch_ncsc_uk_reports() -> list[dict]:
    """Fetch UK NCSC threat reports and advisories via RSS.

    UK NCSC is a Five Eyes partner. Their report feed includes
    threat reports, advisories, and guidance relevant to allied nations.
    """
    logger.info("Fetching NCSC UK reports...")
    entries = []

    try:
        resp = fetch_url(SOURCES["ncsc_uk_reports"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:30]:
                published = ""
                if hasattr(entry, "published"):
                    published = entry.published
                elif hasattr(entry, "updated"):
                    published = entry.updated

                entries.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "published": published,
                    "summary": truncate(entry.get("summary", ""), 300),
                    "source": "NCSC UK",
                })
            logger.info(f"  NCSC UK: {len(feed.entries)} entries")
    except Exception as e:
        logger.error(f"Error fetching NCSC UK: {e}")

    return entries


def fetch_cisa_ics_advisories() -> list[dict]:
    """Fetch CISA ICS-CERT advisories via RSS.

    Industrial control system advisories are directly relevant to
    Australian critical infrastructure under the SOCI Act.
    """
    logger.info("Fetching CISA ICS advisories...")
    entries = []

    try:
        resp = fetch_url(SOURCES["cisa_ics_rss"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:30]:
                published = ""
                if hasattr(entry, "published"):
                    published = entry.published

                entries.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "published": published,
                    "summary": truncate(entry.get("summary", ""), 300),
                    "source": "CISA ICS",
                })
            logger.info(f"  CISA ICS: {len(feed.entries)} entries")
    except Exception as e:
        logger.error(f"Error fetching CISA ICS: {e}")

    return entries


def fetch_cisa_alerts() -> list[dict]:
    """Fetch CISA cybersecurity advisories via RSS."""
    logger.info("Fetching CISA advisories...")
    entries = []

    try:
        resp = fetch_url(SOURCES["cisa_alerts_rss"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:30]:
                published = ""
                if hasattr(entry, "published"):
                    published = entry.published

                entries.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "published": published,
                    "summary": truncate(entry.get("summary", ""), 300),
                    "source": "CISA",
                })
            logger.info(f"  CISA: {len(feed.entries)} entries")
    except Exception as e:
        logger.error(f"Error fetching CISA: {e}")

    return entries


def run():
    """Fetch all advisory sources and save."""
    acsc = fetch_acsc_feeds()
    cccs = fetch_cccs_advisories()
    ncsc_uk = fetch_ncsc_uk_reports()
    cisa = fetch_cisa_alerts()
    cisa_ics = fetch_cisa_ics_advisories()

    all_advisories = acsc + cccs + ncsc_uk + cisa + cisa_ics

    # Sort by date (newest first)
    all_advisories.sort(
        key=lambda x: x.get("published", ""),
        reverse=True
    )

    # Count by source
    by_source = {}
    for a in all_advisories:
        src = a["source"]
        by_source[src] = by_source.get(src, 0) + 1

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_count": len(all_advisories),
        "by_source": by_source,
        "advisories": all_advisories,
    }

    save_data("advisories.json", data)
    return data


if __name__ == "__main__":
    run()
