"""
Fetch advisories, alerts, news, publications, and threats from ASD/ACSC,
AusCERT, and CISA RSS feeds.
"""
import feedparser
from datetime import datetime

from .config import SOURCES
from .utils import logger, save_data, fetch_url, truncate


def fetch_acsc_feeds() -> list[dict]:
    """Fetch all five ACSC RSS feeds."""
    logger.info("Fetching ACSC feeds...")
    entries = []

    for feed_name, feed_key in [
        ("ACSC Alerts", "acsc_alerts_rss"),
        ("ACSC Advisories", "acsc_advisories_rss"),
        ("ACSC News", "acsc_news_rss"),
        ("ACSC Publications", "acsc_publications_rss"),
        ("ACSC Threats", "acsc_threats_rss"),
    ]:
        feed_url = SOURCES[feed_key]
        feed = None
        try:
            # Primary: use fetch_url (respects our retry/timeout logic)
            resp = fetch_url(feed_url)
            if resp:
                feed = feedparser.parse(resp.content)
        except Exception as e:
            logger.warning(f"  fetch_url failed for {feed_name}: {e}")

        # Fallback: let feedparser fetch directly (its own HTTP client)
        if feed is None or not feed.entries:
            try:
                logger.info(f"  Trying feedparser direct fetch for {feed_name}...")
                feed = feedparser.parse(feed_url)
            except Exception as e:
                logger.error(f"  feedparser direct fetch also failed for {feed_name}: {e}")
                continue

        if not feed or not feed.entries:
            logger.warning(f"  {feed_name}: no entries returned")
            continue

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
        logger.info(f"  {feed_name}: {len(feed.entries)} entries")

    return entries


def fetch_auscert_bulletins() -> list[dict]:
    """Fetch AusCERT security bulletins via RSS."""
    logger.info("Fetching AusCERT bulletins...")
    entries = []

    try:
        resp = fetch_url(SOURCES["auscert_rss"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:50]:
                published = ""
                if hasattr(entry, "published"):
                    published = entry.published

                entries.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", ""),
                    "published": published,
                    "summary": truncate(entry.get("summary", ""), 300),
                    "source": "AusCERT",
                })
            logger.info(f"  AusCERT: {len(feed.entries)} entries")
    except Exception as e:
        logger.error(f"Error fetching AusCERT: {e}")

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
    auscert = fetch_auscert_bulletins()
    cisa = fetch_cisa_alerts()

    all_advisories = acsc + auscert + cisa

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
        "fetched_at": datetime.utcnow().isoformat() + "Z",
        "total_count": len(all_advisories),
        "by_source": by_source,
        "advisories": all_advisories,
    }

    save_data("advisories.json", data)
    return data


if __name__ == "__main__":
    run()
