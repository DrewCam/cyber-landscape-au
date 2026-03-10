"""
Fetch advisories, alerts, news, publications, and threats from ASD/ACSC,
AusCERT, and CISA RSS feeds.

Note: cyber.gov.au blocks requests from cloud provider IP ranges (GitHub Actions,
AWS, Azure, etc.). We use multiple proxy strategies to work around this.
"""
import feedparser
from datetime import datetime
from urllib.parse import quote_plus

from .config import SOURCES
from .utils import logger, save_data, fetch_url, truncate


# RSS proxy services that can fetch feeds on our behalf.
# These are public, free services. If one stops working, the next is tried.
_RSS_PROXIES = [
    # AllOrigins - CORS proxy that returns raw content
    lambda url: f"https://api.allorigins.win/raw?url={quote_plus(url)}",
    # cors.sh proxy
    lambda url: f"https://proxy.cors.sh/{url}",
    # Direct (last resort, will likely timeout from cloud IPs)
    lambda url: url,
]


def _fetch_rss_with_proxies(feed_url: str, feed_name: str):
    """Try fetching an RSS feed through multiple proxy routes."""

    for i, proxy_fn in enumerate(_RSS_PROXIES):
        proxied_url = proxy_fn(feed_url)
        is_direct = proxied_url == feed_url
        label = "direct" if is_direct else f"proxy {i + 1}"

        try:
            logger.info(f"  {feed_name}: trying {label}...")
            resp = fetch_url(proxied_url, timeout=30, retries=1)
            if resp and resp.content:
                feed = feedparser.parse(resp.content)
                if feed.entries:
                    logger.info(f"  {feed_name}: {len(feed.entries)} entries via {label}")
                    return feed
                else:
                    logger.warning(f"  {feed_name}: {label} returned no entries")
        except Exception as e:
            logger.warning(f"  {feed_name}: {label} failed: {e}")

    # Final fallback: feedparser's own HTTP client with browser UA
    try:
        logger.info(f"  {feed_name}: trying feedparser direct...")
        feed = feedparser.parse(
            feed_url,
            request_headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                "Accept": "application/rss+xml, application/xml, text/xml, */*",
                "Accept-Language": "en-AU,en;q=0.9",
            }
        )
        if feed and feed.entries:
            logger.info(f"  {feed_name}: {len(feed.entries)} entries via feedparser direct")
            return feed
    except Exception as e:
        logger.warning(f"  {feed_name}: feedparser direct failed: {e}")

    logger.error(f"  {feed_name}: all fetch methods exhausted")
    return None


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
        feed = _fetch_rss_with_proxies(feed_url, feed_name)

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
