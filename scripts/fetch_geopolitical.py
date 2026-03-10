"""
Fetch geopolitical and strategic cyber intelligence:
- MITRE ATT&CK groups (live, enriches threat actor profiles)
- ASPI (Australian Strategic Policy Institute) RSS
- BleepingComputer news (filtered for APAC/AU relevance)
- Static reference data for Australian-specific context
"""
import feedparser
from datetime import datetime, timezone

from .config import SOURCES
from .utils import logger, save_data, fetch_url, truncate


# APAC-relevant country keywords for filtering MITRE groups
_APAC_COUNTRIES = {
    "china", "chinese", "prc",
    "russia", "russian", "gru", "svr", "fsb",
    "north korea", "dprk", "korean",
    "iran", "iranian", "irgc",
    "india", "indian",
    "vietnam", "vietnamese",
    "pakistan", "pakistani",
}

# Australian-specific context that MITRE doesn't have.
# Keyed by mitre_id (intrusion-set--xxx) or by common name.
_AU_RELEVANCE = {
    "G0065": "Directly targeted Australian organisations. Subject of joint ASD advisory (2024).",
    "G0128": "Targeted Australian Parliament (2019). Active against Five Eyes nations.",
    "G0129": "Active in Southeast Asia and Oceania. PlugX malware campaigns targeting APAC.",
    "G0094": "Targets APAC policy researchers and diplomats. Credential harvesting campaigns.",
    "G0032": "Major cryptocurrency theft operations. Active against APAC financial institutions.",
    "G0007": "Global operations affecting Five Eyes partners. Active disinformation campaigns.",
    "G0016": "SolarWinds supply chain attack. Persistent targeting of Western government networks.",
    "G0034": "Destructive attacks on critical infrastructure. NotPetya, Industroyer operations.",
    "G0121": "Active in APAC region targeting government and military entities.",
    # Groups without stable MITRE IDs yet (match by name fragment)
    "Volt Typhoon": "Living-off-the-land techniques against Western critical infrastructure. Five Eyes joint advisory.",
    "Salt Typhoon": "Compromised major telecommunications providers. Potential APAC impact.",
    "Flax Typhoon": "Botnet operations using compromised IoT. Disrupted by FBI (2024).",
}

# Australian cyber policy reference data (static, updates infrequently)
AU_CYBER_POLICY = [
    {
        "name": "Security of Critical Infrastructure Act 2018 (SOCI)",
        "status": "Active (amended 2022)",
        "scope": "11 critical infrastructure sectors",
        "key_requirements": "Risk management programs, incident reporting (12/72hr), government assistance measures",
        "link": "https://www.legislation.gov.au/C2018A00029/latest",
    },
    {
        "name": "Australian Cyber Security Strategy 2023-2030",
        "status": "Active",
        "scope": "National cyber security posture",
        "key_requirements": "Six shields framework, cyber resilience across economy",
        "link": "https://www.homeaffairs.gov.au/cyber-security-subsite/files/2023-cyber-security-strategy.pdf",
    },
    {
        "name": "Privacy Act 1988 (NDB Scheme)",
        "status": "Active (NDB from Feb 2018)",
        "scope": "Organisations with >$3M revenue, health, government",
        "key_requirements": "Mandatory notification of eligible data breaches to OAIC and affected individuals",
        "link": "https://www.legislation.gov.au/C2004A03712/latest",
    },
    {
        "name": "Essential Eight Maturity Model",
        "status": "Active (updated 2023)",
        "scope": "Commonwealth entities (mandated), recommended for all",
        "key_requirements": "Eight mitigation strategies across three maturity levels",
        "link": "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
    },
    {
        "name": "Cyber Security Act 2024",
        "status": "Active (from 2024)",
        "scope": "Ransomware reporting, smart device security, Cyber Incident Review Board",
        "key_requirements": "Mandatory ransomware payment reporting, security standards for IoT devices",
        "link": "https://www.legislation.gov.au/C2024A00105/latest",
    },
    {
        "name": "AUKUS Pillar II",
        "status": "Active",
        "scope": "Trilateral defence technology cooperation (AU/UK/US)",
        "key_requirements": "Advanced cyber capabilities, AI, quantum technology sharing",
        "link": "https://www.defence.gov.au/about/strategic-planning/aukus",
    },
]


def fetch_mitre_threat_actors() -> list[dict]:
    """Fetch threat actor (intrusion-set) data from MITRE ATT&CK.

    Downloads the enterprise-attack STIX bundle from GitHub and extracts
    groups relevant to APAC/Five Eyes targeting. Enriches with Australian-
    specific relevance notes from our static reference data.
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
        all_text = (name + " " + description + " " + " ".join(aliases)).lower()

        # Check if group is APAC-relevant
        is_apac = any(kw in all_text for kw in _APAC_COUNTRIES)
        if not is_apac:
            continue

        # Extract MITRE ATT&CK group ID (e.g. G0065) from external references
        mitre_id = ""
        mitre_url = ""
        for ref in g.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                mitre_url = ref.get("url", "")
                break

        # Determine attribution from description
        attribution = _extract_attribution(description, name)

        # Extract target sectors from description
        targets = _extract_targets(description)

        # Look up Australian relevance
        relevance = _AU_RELEVANCE.get(mitre_id, "")
        if not relevance:
            # Try matching by name fragment
            for key, val in _AU_RELEVANCE.items():
                if key in name:
                    relevance = val
                    break
        if not relevance:
            relevance = "APAC-relevant based on MITRE ATT&CK attribution and targeting data."

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
            "relevance": relevance,
            "mitre_id": mitre_id,
            "mitre_url": mitre_url,
            "description": truncate(description, 400),
            "technique_count": tech_count,
            "active": not g.get("revoked", False),
            "last_modified": g.get("modified", ""),
            "source": "MITRE ATT&CK",
        })

    # Sort by technique count (most active first)
    apac_groups.sort(key=lambda x: x["technique_count"], reverse=True)
    logger.info(f"  MITRE ATT&CK: {len(apac_groups)} APAC-relevant groups")
    return apac_groups


def _extract_attribution(description: str, name: str) -> str:
    """Best-effort extraction of nation-state attribution from MITRE description."""
    desc_lower = description.lower()
    name_lower = name.lower()
    combined = desc_lower + " " + name_lower

    if any(kw in combined for kw in ["china", "chinese", "prc"]):
        if "mss" in combined:
            return "China / MSS"
        if "pla" in combined:
            return "China / PLA"
        return "China"
    if any(kw in combined for kw in ["russia", "russian"]):
        if "gru" in combined:
            return "Russia / GRU"
        if "svr" in combined:
            return "Russia / SVR"
        if "fsb" in combined:
            return "Russia / FSB"
        return "Russia"
    if any(kw in combined for kw in ["north korea", "dprk"]):
        if "rgb" in combined or "reconnaissance general bureau" in combined:
            return "North Korea / RGB"
        return "North Korea"
    if any(kw in combined for kw in ["iran", "iranian"]):
        if "irgc" in combined:
            return "Iran / IRGC"
        if "mois" in combined:
            return "Iran / MOIS"
        return "Iran"
    if any(kw in combined for kw in ["india", "indian"]):
        return "India (suspected)"
    if any(kw in combined for kw in ["vietnam", "vietnamese"]):
        return "Vietnam"
    if any(kw in combined for kw in ["pakistan", "pakistani"]):
        return "Pakistan"
    return "Unknown"


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
                        "published": getattr(entry, "published", ""),
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
        resp = fetch_url(SOURCES["bom_cyber_news"])
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
                    "zero-day", "supply chain", "telecom",
                ]
                if any(kw in combined for kw in apac_keywords):
                    entries.append({
                        "title": entry.get("title", ""),
                        "link": entry.get("link", ""),
                        "published": getattr(entry, "published", ""),
                        "summary": truncate(entry.get("summary", ""), 300),
                        "source": "BleepingComputer",
                    })
            logger.info(f"  BleepingComputer: {len(entries)} APAC-relevant articles")
    except Exception as e:
        logger.error(f"Error fetching BleepingComputer: {e}")

    return entries


def run():
    """Fetch all geopolitical/strategic data and save."""
    # Live MITRE ATT&CK threat actors (replaces static list)
    threat_actors = fetch_mitre_threat_actors()

    aspi = fetch_aspi_feed()
    bleeping = fetch_bleeping_computer()
    all_news = aspi + bleeping
    all_news.sort(key=lambda x: x.get("published", ""), reverse=True)

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "threat_actors": threat_actors,
        "au_cyber_policy": AU_CYBER_POLICY,
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
