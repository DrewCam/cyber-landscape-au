"""
Fetch OSINT data from open sources:
- GreyNoise Community API (internet scanning trends)
- AlienVault OTX (threat pulses)
"""
from datetime import datetime, timezone
from collections import Counter

from .config import SOURCES, GREYNOISE_API_KEY, OTX_API_KEY
from .utils import logger, save_data, fetch_url


def fetch_greynoise_trends() -> dict:
    """Fetch internet noise/scanning trends from GreyNoise Community API (v3).

    The community endpoint provides per-IP classification (noise/RIOT/unknown).
    We query a set of well-known IPs to demonstrate the classification capability
    and report API availability.
    """
    logger.info("Fetching GreyNoise data (v3 community)...")

    if not GREYNOISE_API_KEY:
        logger.warning("  No GREYNOISE_API_KEY set, skipping GreyNoise")
        return {"available": False, "note": "Set GREYNOISE_API_KEY for live data"}

    headers = {"key": GREYNOISE_API_KEY}

    # Query a handful of well-known scanner/benign IPs to show classification
    sample_ips = [
        "8.8.8.8",       # Google DNS (likely RIOT/benign)
        "1.1.1.1",       # Cloudflare DNS
        "159.203.176.25", # Known scanner
    ]
    results = []
    for ip in sample_ips:
        url = f"{SOURCES['greynoise_community']}{ip}"
        resp = fetch_url(url, headers=headers)
        if resp:
            try:
                info = resp.json()
                results.append({
                    "ip": ip,
                    "noise": info.get("noise", False),
                    "riot": info.get("riot", False),
                    "classification": info.get("classification", "unknown"),
                    "name": info.get("name", ""),
                    "message": info.get("message", ""),
                })
            except Exception:
                pass

    logger.info(f"  GreyNoise: queried {len(results)} IPs")
    return {
        "available": True,
        "sample_results": results,
        "note": "GreyNoise Community API v3 - per-IP classification",
    }


def fetch_otx_pulses() -> list[dict]:
    """Fetch recent OTX pulses (threat intelligence)."""
    logger.info("Fetching AlienVault OTX pulses...")

    if not OTX_API_KEY:
        logger.warning("  No OTX_API_KEY set, using public feed")
        # Fetch public pulses
        url = "https://otx.alienvault.com/api/v1/pulses/activity"
        resp = fetch_url(url)
    else:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        resp = fetch_url(SOURCES["otx_pulses"], headers=headers, params={"limit": 50})

    if not resp:
        return []

    try:
        data = resp.json()
        pulses = data.get("results", [])
        logger.info(f"  OTX: {len(pulses)} pulses")

        return [{
            "name": p.get("name", ""),
            "description": (p.get("description", "") or "")[:300],
            "created": p.get("created", ""),
            "modified": p.get("modified", ""),
            "tags": p.get("tags", [])[:10],
            "targeted_countries": p.get("targeted_countries", []),
            "adversary": p.get("adversary", ""),
            "malware_families": [
                m.get("display_name", str(m)) if isinstance(m, dict) else str(m)
                for m in p.get("malware_families", [])
            ],
            "attack_ids": [
                a.get("display_name", str(a)) if isinstance(a, dict) else str(a)
                for a in p.get("attack_ids", [])
            ],
            "indicator_count": len(p.get("indicators", [])),
            "pulse_source": p.get("pulse_source", ""),
        } for p in pulses[:50]]
    except Exception as e:
        logger.error(f"Error parsing OTX pulses: {e}")
        return []


def analyse_osint(otx_pulses: list) -> dict:
    """Produce summary statistics from OSINT data."""
    # Top tags across OTX pulses
    all_tags = []
    for p in otx_pulses:
        all_tags.extend(p.get("tags", []))
    top_tags = Counter(t.lower() for t in all_tags if t).most_common(20)

    # Countries targeted
    all_countries = []
    for p in otx_pulses:
        all_countries.extend(p.get("targeted_countries", []))
    country_dist = Counter(all_countries).most_common(15)

    # Adversaries mentioned
    adversaries = Counter(
        p.get("adversary", "") for p in otx_pulses if p.get("adversary")
    ).most_common(10)

    # Malware families
    all_malware = []
    for p in otx_pulses:
        all_malware.extend(p.get("malware_families", []))
    malware_dist = Counter(m for m in all_malware if m).most_common(15)

    # ATT&CK techniques
    all_attacks = []
    for p in otx_pulses:
        all_attacks.extend(p.get("attack_ids", []))
    attack_dist = Counter(a for a in all_attacks if a).most_common(15)

    # Australia-relevant pulses
    au_relevant = [
        p for p in otx_pulses
        if "AU" in p.get("targeted_countries", [])
        or any(t.lower() in ["australia", "australian", "apac", "oceania"]
               for t in p.get("tags", []))
    ]

    return {
        "total_pulses": len(otx_pulses),
        "top_tags": [{"tag": t, "count": c} for t, c in top_tags],
        "targeted_countries": [{"country": c, "count": n} for c, n in country_dist],
        "adversaries": [{"name": a, "count": c} for a, c in adversaries],
        "malware_families": [{"family": m, "count": c} for m, c in malware_dist],
        "attack_techniques": [{"technique": a, "count": c} for a, c in attack_dist],
        "australia_relevant_count": len(au_relevant),
        "australia_relevant": au_relevant[:10],
    }


def run():
    """Fetch all OSINT sources and save."""
    greynoise = fetch_greynoise_trends()
    otx_pulses = fetch_otx_pulses()
    analysis = analyse_osint(otx_pulses)

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "greynoise": greynoise,
        "otx_analysis": analysis,
        "otx_pulses": otx_pulses[:30],
    }

    save_data("osint.json", data)
    return data


if __name__ == "__main__":
    run()
