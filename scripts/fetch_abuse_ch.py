"""
Fetch threat data from abuse.ch services:
- URLhaus (malicious URLs)
- ThreatFox (IOCs)
- MalwareBazaar (malware samples)
"""
from datetime import datetime, timezone
from collections import Counter

from .config import SOURCES
from .utils import logger, save_data, fetch_url


def fetch_urlhaus_recent() -> list[dict]:
    """Fetch recent malicious URLs from URLhaus."""
    logger.info("Fetching URLhaus recent URLs...")
    resp = fetch_url(
        SOURCES["urlhaus_recent"],
        method="POST",
        json_body={"limit": 100}
    )
    if not resp:
        # Try GET as fallback
        resp = fetch_url(SOURCES["urlhaus_recent"])
        if not resp:
            return []

    try:
        data = resp.json()
        urls = data.get("urls", [])
        logger.info(f"  URLhaus: {len(urls)} recent URLs")

        return [{
            "url": u.get("url", ""),
            "url_status": u.get("url_status", ""),
            "threat": u.get("threat", ""),
            "tags": u.get("tags", []),
            "host": u.get("host", ""),
            "date_added": u.get("date_added", ""),
            "reporter": u.get("reporter", ""),
        } for u in urls[:100]]
    except Exception as e:
        logger.error(f"Error parsing URLhaus: {e}")
        return []


def fetch_threatfox_iocs(days: int = 7) -> list[dict]:
    """Fetch recent IOCs from ThreatFox."""
    logger.info(f"Fetching ThreatFox IOCs (last {days} days)...")
    resp = fetch_url(
        SOURCES["threatfox_iocs"],
        method="POST",
        json_body={"query": "get_iocs", "days": days}
    )
    if not resp:
        return []

    try:
        data = resp.json()
        iocs = data.get("data", [])
        if isinstance(iocs, list):
            logger.info(f"  ThreatFox: {len(iocs)} IOCs")
            return [{
                "ioc": i.get("ioc", ""),
                "ioc_type": i.get("ioc_type", ""),
                "threat_type": i.get("threat_type", ""),
                "malware": i.get("malware_printable", ""),
                "confidence": i.get("confidence_level", 0),
                "first_seen": i.get("first_seen_utc", ""),
                "tags": i.get("tags", []),
            } for i in iocs[:200]]
    except Exception as e:
        logger.error(f"Error parsing ThreatFox: {e}")

    return []


def fetch_malwarebazaar_recent() -> list[dict]:
    """Fetch recent malware samples from MalwareBazaar."""
    logger.info("Fetching MalwareBazaar recent samples...")
    resp = fetch_url(
        SOURCES["malwarebazaar_recent"],
        method="POST",
        json_body={"query": "get_recent", "selector": "time"}
    )
    if not resp:
        return []

    try:
        data = resp.json()
        samples = data.get("data", [])
        if isinstance(samples, list):
            logger.info(f"  MalwareBazaar: {len(samples)} recent samples")
            return [{
                "sha256": s.get("sha256_hash", ""),
                "file_type": s.get("file_type", ""),
                "file_size": s.get("file_size", 0),
                "signature": s.get("signature", ""),
                "tags": s.get("tags", []),
                "first_seen": s.get("first_seen", ""),
                "delivery_method": s.get("delivery_method", ""),
            } for s in samples[:100]]
    except Exception as e:
        logger.error(f"Error parsing MalwareBazaar: {e}")

    return []


def analyse_threats(urlhaus: list, threatfox: list, malwarebazaar: list) -> dict:
    """Produce summary statistics from threat data."""
    # URLhaus threat types
    url_threats = Counter(u.get("threat", "unknown") for u in urlhaus)
    url_statuses = Counter(u.get("url_status", "unknown") for u in urlhaus)

    # ThreatFox malware families
    tf_malware = Counter(i.get("malware", "unknown") for i in threatfox)
    tf_types = Counter(i.get("ioc_type", "unknown") for i in threatfox)

    # MalwareBazaar file types and signatures
    mb_file_types = Counter(s.get("file_type", "unknown") for s in malwarebazaar)
    mb_signatures = Counter(s.get("signature", "unknown") for s in malwarebazaar if s.get("signature"))

    # Flatten all tags
    all_tags = []
    for item in urlhaus:
        all_tags.extend(item.get("tags") or [])
    for item in threatfox:
        all_tags.extend(item.get("tags") or [])
    for item in malwarebazaar:
        all_tags.extend(item.get("tags") or [])
    top_tags = Counter(t for t in all_tags if t).most_common(20)

    return {
        "urlhaus": {
            "total": len(urlhaus),
            "threat_types": dict(url_threats.most_common(10)),
            "statuses": dict(url_statuses),
        },
        "threatfox": {
            "total": len(threatfox),
            "top_malware": dict(tf_malware.most_common(10)),
            "ioc_types": dict(tf_types),
        },
        "malwarebazaar": {
            "total": len(malwarebazaar),
            "file_types": dict(mb_file_types.most_common(10)),
            "top_signatures": dict(mb_signatures.most_common(10)),
        },
        "top_tags": [{"tag": t, "count": c} for t, c in top_tags],
    }


def run():
    """Fetch all abuse.ch data and save."""
    urlhaus = fetch_urlhaus_recent()
    threatfox = fetch_threatfox_iocs()
    malwarebazaar = fetch_malwarebazaar_recent()
    analysis = analyse_threats(urlhaus, threatfox, malwarebazaar)

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "analysis": analysis,
        "urlhaus_urls": urlhaus[:50],
        "threatfox_iocs": threatfox[:50],
        "malwarebazaar_samples": malwarebazaar[:50],
    }

    save_data("threats.json", data)
    return data


if __name__ == "__main__":
    run()
