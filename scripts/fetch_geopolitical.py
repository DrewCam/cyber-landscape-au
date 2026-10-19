"""
Fetch geopolitical and strategic cyber intelligence:
- MITRE ATT&CK groups (threat actor profiles)
- ASPI (Australian Strategic Policy Institute) RSS
- BleepingComputer news (filtered for APAC/AU relevance)
"""
import re

import feedparser
from datetime import datetime, timezone

from .config import SOURCES
from .utils import logger, save_data, fetch_url, truncate, to_iso


def fetch_mitre_threat_actors() -> list[dict]:
    """Fetch threat actor (intrusion-set) data from MITRE ATT&CK.

    Downloads the enterprise-attack STIX bundle from GitHub and keeps groups
    whose descriptions attribute them to a tracked country (see _ATTRIBUTION).
    """
    logger.info("Fetching MITRE ATT&CK threat groups...")
    url = SOURCES.get("mitre_attack_enterprise", "")
    if not url:
        logger.warning("  No MITRE ATT&CK URL configured")
        return []

    resp = fetch_url(url, timeout=60)
    if not resp:
        logger.warning("  Could not fetch MITRE ATT&CK data")
        return []

    try:
        bundle = resp.json()
    except Exception as e:
        logger.error(f"  Error parsing MITRE ATT&CK JSON: {e}")
        return []

    objects = bundle.get("objects", [])

    # Extract intrusion-sets (threat groups)
    groups = [o for o in objects if o.get("type") == "intrusion-set"]
    logger.info(f"  MITRE ATT&CK: {len(groups)} total groups")

    # Build technique-count lookup: group_id -> number of techniques used
    # Relationships of type "uses" where source is intrusion-set and target is attack-pattern
    technique_counts = {}
    for o in objects:
        if (o.get("type") == "relationship"
                and o.get("relationship_type") == "uses"
                and o.get("source_ref", "").startswith("intrusion-set--")
                and o.get("target_ref", "").startswith("attack-pattern--")):
            src = o["source_ref"]
            technique_counts[src] = technique_counts.get(src, 0) + 1

    # Filter for APAC-relevant groups
    apac_groups = []
    for g in groups:
        name = g.get("name", "")
        description = g.get("description", "")
        aliases = g.get("aliases", [])

        # Keep groups whose description ties them to one of the tracked countries
        attribution = _extract_attribution(description, name)
        if attribution == "Unknown":
            continue

        # Extract MITRE ATT&CK group ID (e.g. G0065) from external references
        mitre_id = ""
        mitre_url = ""
        for ref in g.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                mitre_url = ref.get("url", "")
                break

        # Extract target sectors from description
        targets = _extract_targets(description)

        # Check if revoked or deprecated
        if g.get("revoked") or g.get("x_mitre_deprecated"):
            continue

        stix_id = g.get("id", "")
        tech_count = technique_counts.get(stix_id, 0)

        apac_groups.append({
            "name": name,
            "aliases": [a for a in aliases if a != name][:5],
            "attribution": attribution,
            "targets": targets,
            "mitre_id": mitre_id,
            "mitre_url": mitre_url,
            "description": truncate(description, 400),
            "technique_count": tech_count,
            "last_modified": g.get("modified", ""),
            "source": "MITRE ATT&CK",
        })

    # Sort by number of documented ATT&CK techniques
    apac_groups.sort(key=lambda x: x["technique_count"], reverse=True)
    logger.info(f"  MITRE ATT&CK: {len(apac_groups)} APAC-relevant groups")
    return apac_groups


# Country keywords and the agency names MITRE uses in group descriptions.
# Matched as whole words; "pla" or "prc" would otherwise hit "platform", "practices".
_ATTRIBUTION = [
    ("China", ["china", "chinese", "prc"], [("MSS", ["mss"]), ("PLA", ["pla"])]),
    ("Russia", ["russia", "russian"], [("GRU", ["gru"]), ("SVR", ["svr"]), ("FSB", ["fsb"])]),
    ("North Korea", ["north korea", "north korean", "dprk", "democratic people's republic of korea"],
     [("RGB", ["rgb", "reconnaissance general bureau"])]),
    ("Iran", ["iran", "iranian"], [("IRGC", ["irgc"]), ("MOIS", ["mois"])]),
    ("India", ["india", "indian"], []),
    ("Vietnam", ["vietnam", "vietnamese"], []),
    ("Pakistan", ["pakistan", "pakistani"], []),
]


def _first_match(text: str, keywords: list[str]) -> int | None:
    """Position of the earliest whole-word keyword match, or None."""
    positions = [m.start() for kw in keywords
                 for m in [re.search(rf"\b{re.escape(kw)}\b", text)] if m]
    return min(positions) if positions else None


def _extract_attribution(description: str, name: str) -> str:
    """Best-effort nation-state attribution from a MITRE group description.

    MITRE descriptions open with the group's origin ("X is a North Korea-based
    group...") and mention victim countries later, so the country named
    earliest is taken as the attribution.
    """
    text = (description + " " + name).lower()
    best = None
    for country, keywords, agencies in _ATTRIBUTION:
        pos = _first_match(text, keywords)
        if pos is not None and (best is None or pos < best[0]):
            best = (pos, country, agencies)
    if best is None:
        return "Unknown"

    _, country, agencies = best
    for agency, keywords in agencies:
        if _first_match(text, keywords) is not None:
            return f"{country} / {agency}"
    return country


def _extract_targets(description: str) -> str:
    """Extract likely target sectors from MITRE description."""
    desc_lower = description.lower()
    sectors = []
    sector_keywords = {
        "government": "Government",
        "military": "Military",
        "defence": "Defence",
        "defense": "Defence",
        "financial": "Financial",
        "banking": "Financial",
        "energy": "Energy",
        "telecommunication": "Telecommunications",
        "telecom": "Telecommunications",
        "healthcare": "Healthcare",
        "health": "Healthcare",
        "technology": "Technology",
        "critical infrastructure": "Critical Infrastructure",
        "aerospace": "Aerospace",
        "maritime": "Maritime",
        "education": "Education",
        "media": "Media",
        "diplomatic": "Diplomatic",
        "cryptocurrency": "Cryptocurrency",
    }
    for keyword, label in sector_keywords.items():
        if keyword in desc_lower and label not in sectors:
            sectors.append(label)
    return ", ".join(sectors[:5]) if sectors else "Multiple sectors"


def fetch_aspi_feed() -> list[dict]:
    """Fetch ASPI strategic analysis RSS feed."""
    logger.info("Fetching ASPI strategic feed...")
    entries = []

    try:
        resp = fetch_url(SOURCES["aspi_rss"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:30]:
                title_lower = entry.get("title", "").lower()
                summary_lower = entry.get("summary", "").lower()
                cyber_keywords = [
                    "cyber", "digital", "technology", "security", "intelligence",
                    "china", "russia", "espionage", "disinformation", "critical infrastructure",
                    "data", "privacy", "hack", "breach", "threat", "defence", "military",
                    "indo-pacific", "aukus", "five eyes", "ransomware"
                ]
                if any(kw in title_lower or kw in summary_lower for kw in cyber_keywords):
                    entries.append({
                        "title": entry.get("title", ""),
                        "link": entry.get("link", ""),
                        "published": to_iso(entry.get("published") or entry.get("updated") or ""),
                        "summary": truncate(entry.get("summary", ""), 300),
                        "source": "ASPI",
                    })
            logger.info(f"  ASPI: {len(entries)} cyber-relevant articles")
    except Exception as e:
        logger.error(f"Error fetching ASPI: {e}")

    return entries


def fetch_bleeping_computer() -> list[dict]:
    """Fetch BleepingComputer news, filtered for APAC relevance."""
    logger.info("Fetching BleepingComputer news...")
    entries = []

    try:
        resp = fetch_url(SOURCES["bleepingcomputer_rss"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:50]:
                title_lower = entry.get("title", "").lower()
                summary_lower = entry.get("summary", "").lower()
                combined = title_lower + " " + summary_lower

                apac_keywords = [
                    "australia", "australian", "apac", "asia-pacific",
                    "china", "chinese", "russia", "russian",
                    "north korea", "critical infrastructure",
                    "apt", "state-sponsored", "ransomware",
                    "zero-day", "supply chain", "supply-chain", "telecom",
                    "nation-state", "espionage", "spyware", "data breach",
                    "japan", "korea", "taiwan", "india", "new zealand", "pacific",
                ]
                if any(kw in combined for kw in apac_keywords):
                    entries.append({
                        "title": entry.get("title", ""),
                        "link": entry.get("link", ""),
                        "published": to_iso(entry.get("published") or entry.get("updated") or ""),
                        "summary": truncate(entry.get("summary", ""), 300),
                        "source": "BleepingComputer",
                    })
            logger.info(f"  BleepingComputer: {len(entries)} APAC-relevant articles")
    except Exception as e:
        logger.error(f"Error fetching BleepingComputer: {e}")

    return entries


def run():
    """Fetch all geopolitical/strategic data and save."""
    threat_actors = fetch_mitre_threat_actors()

    aspi = fetch_aspi_feed()
    bleeping = fetch_bleeping_computer()
    all_news = aspi + bleeping
    all_news.sort(key=lambda x: x.get("published", ""), reverse=True)

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "threat_actors": threat_actors,
        "news": all_news,
        "news_by_source": {
            "ASPI": len(aspi),
            "BleepingComputer": len(bleeping),
        },
    }

    save_data("geopolitical.json", data)
    return data


if __name__ == "__main__":
    run()
