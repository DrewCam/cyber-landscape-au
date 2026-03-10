"""
Fetch internet exposure data from Shodan.
Requires SHODAN_API_KEY environment variable.

Queries Australian IP space and common exposed services.
"""
from datetime import datetime, timezone
from collections import Counter

from .config import SOURCES, SHODAN_API_KEY
from .utils import logger, save_data, fetch_url


SHODAN_API_BASE = "https://api.shodan.io"

# Australian-relevant search queries
AU_QUERIES = [
    {"name": "Australian RDP exposed", "query": "port:3389 country:AU"},
    {"name": "Australian SMB exposed", "query": "port:445 country:AU"},
    {"name": "Australian industrial (Modbus)", "query": "port:502 country:AU"},
    {"name": "Australian VNC exposed", "query": "port:5900 country:AU"},
    {"name": "Australian Telnet exposed", "query": "port:23 country:AU"},
    {"name": "Australian MongoDB exposed", "query": "port:27017 country:AU"},
    {"name": "Australian Elasticsearch exposed", "query": "port:9200 country:AU"},
    {"name": "Australian Redis exposed", "query": "port:6379 country:AU"},
]


def fetch_shodan_host_count(query: str) -> dict | None:
    """Get count of hosts matching a Shodan query."""
    if not SHODAN_API_KEY:
        return None

    url = f"{SHODAN_API_BASE}/shodan/host/count"
    params = {"key": SHODAN_API_KEY, "query": query}
    resp = fetch_url(url, params=params)
    if not resp:
        return None

    try:
        return resp.json()
    except Exception:
        return None


def fetch_shodan_summary() -> dict:
    """Fetch Shodan summary data for Australian exposure."""
    logger.info("Fetching Shodan Australian exposure data...")

    if not SHODAN_API_KEY:
        logger.warning("  No SHODAN_API_KEY set, skipping Shodan queries")
        return {
            "available": False,
            "note": "Set SHODAN_API_KEY environment variable for live Shodan data",
        }

    # API info (check credits)
    info_resp = fetch_url(
        f"{SHODAN_API_BASE}/api-info",
        params={"key": SHODAN_API_KEY}
    )
    api_info = {}
    if info_resp:
        api_info = info_resp.json()
        logger.info(f"  Shodan API credits remaining: scan={api_info.get('scan_credits', '?')}, query={api_info.get('query_credits', '?')}")

    # Run AU exposure queries
    exposure_results = []
    for q in AU_QUERIES:
        result = fetch_shodan_host_count(q["query"])
        if result:
            count = result.get("total", 0)
            exposure_results.append({
                "name": q["name"],
                "query": q["query"],
                "count": count,
                "facets": result.get("facets", {}),
            })
            logger.info(f"  {q['name']}: {count:,} hosts")
        else:
            exposure_results.append({
                "name": q["name"],
                "query": q["query"],
                "count": 0,
                "error": "Query failed",
            })

    # Top ports in AU
    top_ports_resp = fetch_shodan_host_count("country:AU")
    au_total = 0
    if top_ports_resp:
        au_total = top_ports_resp.get("total", 0)

    return {
        "available": True,
        "api_credits": {
            "scan": api_info.get("scan_credits", 0),
            "query": api_info.get("query_credits", 0),
        },
        "au_total_hosts": au_total,
        "exposure_results": exposure_results,
    }


def fetch_shodan_exploits_search(query: str = "australia") -> list[dict]:
    """Search Shodan exploits database for relevant entries."""
    if not SHODAN_API_KEY:
        return []

    url = f"{SHODAN_API_BASE}/api/search"
    params = {"key": SHODAN_API_KEY, "query": query}
    resp = fetch_url(url, params=params)
    if not resp:
        return []

    try:
        data = resp.json()
        return data.get("matches", [])[:20]
    except Exception:
        return []


def run():
    """Fetch all Shodan data and save."""
    summary = fetch_shodan_summary()

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "shodan": summary,
    }

    save_data("shodan.json", data)
    return data


if __name__ == "__main__":
    run()
