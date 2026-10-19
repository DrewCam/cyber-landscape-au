"""
Fetch advisories, alerts and publications from ASD/ACSC, Five Eyes partner
CERTs (CCCS, NCSC UK), CISA, and CISA ICS-CERT RSS/Atom feeds.

All feeds are fetched directly from the publisher's official endpoint with an
honest, identifiable User-Agent. If a publisher refuses or times out (cyber.gov.au
is often unreachable from cloud runners), that source is simply reported as
unavailable for this build; no proxies, spoofing or scraped caches are used.
"""
import feedparser
from datetime import datetime, timezone

from .config import SOURCES
from .utils import logger, save_data, fetch_url, truncate, to_iso


ACSC_FEEDS = [
    ("ACSC Alerts", "acsc_alerts_rss"),
    ("ACSC Advisories", "acsc_advisories_rss"),
    ("ACSC Publications", "acsc_publications_rss"),
]


def _fetch_feed(url: str, source: str, limit: int, **fetch_kwargs) -> list[dict]:
    """Fetch and parse one RSS/Atom feed into advisory entries."""
    resp = fetch_url(url, **fetch_kwargs)
    if not resp:
        logger.warning(f"  {source}: unavailable")
        return []

    try:
        feed = feedparser.parse(resp.content)
    except Exception as e:
        logger.error(f"  {source}: could not parse feed: {e}")
        return []

    entries = []
    for entry in feed.entries[:limit]:
        published = entry.get("published") or entry.get("updated") or ""
        entries.append({
            "title": entry.get("title", "Untitled"),
            "link": entry.get("link", ""),
            "published": to_iso(published),
            "summary": truncate(entry.get("summary", ""), 300),
            "source": source,
        })
    logger.info(f"  {source}: {len(entries)} entries")
    return entries


def fetch_acsc_feeds() -> list[dict]:
    """Fetch ASD/ACSC RSS feeds directly from cyber.gov.au.

    cyber.gov.au frequently does not respond to cloud/datacenter IPs. If the
    first feed fails we assume the site is unreachable from this host and skip
    the rest rather than waiting on every timeout.
    """
    logger.info("Fetching ASD/ACSC feeds...")
    all_entries = []
    for source, key in ACSC_FEEDS:
        entries = _fetch_feed(SOURCES[key], source, 50, timeout=20, retries=1)
        if not entries and not all_entries:
            logger.warning("  cyber.gov.au unreachable from this host; ACSC feeds skipped this build")
            break
        all_entries.extend(entries)
    return all_entries


def run():
    """Fetch all advisory sources and save."""
    acsc = fetch_acsc_feeds()

    logger.info("Fetching Five Eyes partner and CISA feeds...")
    cccs = _fetch_feed(SOURCES["cccs_advisories"], "CCCS", 50)
    ncsc_uk = _fetch_feed(SOURCES["ncsc_uk_reports"], "NCSC UK", 30)
    cisa = _fetch_feed(SOURCES["cisa_alerts_rss"], "CISA", 30)
    cisa_ics = _fetch_feed(SOURCES["cisa_ics_rss"], "CISA ICS", 30)

    all_advisories = acsc + cccs + ncsc_uk + cisa + cisa_ics

    # Sort by date (newest first); dates are ISO 8601 so string order is chronological
    all_advisories.sort(key=lambda x: x.get("published", ""), reverse=True)

    # Count by source
    by_source = {}
    for a in all_advisories:
        src = a["source"]
        by_source[src] = by_source.get(src, 0) + 1

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_count": len(all_advisories),
        "by_source": by_source,
        "acsc_available": bool(acsc),
        "advisories": all_advisories,
    }

    save_data("advisories.json", data)
    return data


if __name__ == "__main__":
    run()
