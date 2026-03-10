"""
Fetch advisories and alerts from ASD/ACSC and AusCERT RSS feeds.
"""
import feedparser
from datetime import datetime

from .config import SOURCES
from .utils import logger, save_data, fetch_url, truncate


def fetch_acsc_advisories() -> list[dict]:
    """Fetch ACSC alerts and advisories via RSS."""
    logger.info("Fetching ACSC advisories...")
    entries = []

    for feed_name, feed_url in [
        ("ACSC Alerts", SOURCES["acsc_alerts_rss"]),
        ("ACSC Publications", SOURCES["acsc_publications_rss"]),
    ]:
        try:
            resp = fetch_url(feed_url)
            if not resp:
                continue
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
                    "source": feed_name,
                })
            logger.info(f"  {feed_name}: {len(feed.entries)} entries")
        except Exception as e:
            logger.error(f"Error fetching {feed_name}: {e}")

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
    acsc = fetch_acsc_advisories()
    auscert = fetch_auscert_bulletins()
    cisa = fetch_cisa_alerts()

    all_advisories = acsc + auscert + cisa

    # Sort by date (newest first)
    all_advisories.sort(
        key=lambda x: x.get("published", ""),
        reverse=True
    )

    data = {
        "fetched_at": datetime.utcnow().isoformat() + "Z",
        "total_count": len(all_advisories),
        "by_source": {
            "ACSC": len(acsc),
            "AusCERT": len(auscert),
            "CISA": len(cisa),
        },
        "advisories": all_advisories,
    }

    save_data("advisories.json", data)
    return data


if __name__ == "__main__":
    run()
