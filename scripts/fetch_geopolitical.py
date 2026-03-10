"""
Fetch geopolitical and strategic cyber intelligence:
- ASPI (Australian Strategic Policy Institute) RSS
- BleepingComputer news (filtered for APAC/AU relevance)
- Static reference data for APAC threat actors
"""
import feedparser
from datetime import datetime, timezone

from .config import SOURCES
from .utils import logger, save_data, fetch_url, truncate


# Known APAC-linked threat actor groups (reference data)
APAC_THREAT_ACTORS = [
    {
        "name": "APT40 (Leviathan)",
        "attribution": "China / MSS (Hainan)",
        "targets": "Maritime, Defence, Government, Research",
        "relevance": "Directly targeted Australian organisations. Subject of joint ASD advisory (2024).",
        "mitre_id": "G0065",
        "active": True,
    },
    {
        "name": "APT31 (Zirconium)",
        "attribution": "China / MSS",
        "targets": "Government, Technology, Defence",
        "relevance": "Targeted Australian Parliament (2019). Active against Five Eyes nations.",
        "mitre_id": "G0128",
        "active": True,
    },
    {
        "name": "Mustang Panda (Bronze President)",
        "attribution": "China",
        "targets": "Government, NGOs, Telecommunications",
        "relevance": "Active in Southeast Asia and Oceania. PlugX malware campaigns targeting APAC.",
        "mitre_id": "G0129",
        "active": True,
    },
    {
        "name": "Volt Typhoon",
        "attribution": "China",
        "targets": "Critical Infrastructure, Communications, Energy",
        "relevance": "Living-off-the-land techniques against Western critical infrastructure. Five Eyes joint advisory.",
        "mitre_id": "",
        "active": True,
    },
    {
        "name": "Salt Typhoon",
        "attribution": "China",
        "targets": "Telecommunications, ISPs",
        "relevance": "Compromised major telecommunications providers. Potential APAC impact.",
        "mitre_id": "",
        "active": True,
    },
    {
        "name": "Flax Typhoon",
        "attribution": "China",
        "targets": "IoT devices, Critical Infrastructure",
        "relevance": "Botnet operations using compromised IoT. Disrupted by FBI (2024).",
        "mitre_id": "",
        "active": True,
    },
    {
        "name": "Kimsuky (Velvet Chollima)",
        "attribution": "North Korea / RGB",
        "targets": "Government, Research, Think Tanks",
        "relevance": "Targets APAC policy researchers and diplomats. Credential harvesting campaigns.",
        "mitre_id": "G0094",
        "active": True,
    },
    {
        "name": "Lazarus Group",
        "attribution": "North Korea / RGB",
        "targets": "Financial, Cryptocurrency, Defence",
        "relevance": "Major cryptocurrency theft operations. Active against APAC financial institutions.",
        "mitre_id": "G0032",
        "active": True,
    },
    {
        "name": "APT28 (Fancy Bear)",
        "attribution": "Russia / GRU",
        "targets": "Government, Military, Media",
        "relevance": "Global operations affecting Five Eyes partners. Active disinformation campaigns.",
        "mitre_id": "G0007",
        "active": True,
    },
    {
        "name": "APT29 (Cozy Bear)",
        "attribution": "Russia / SVR",
        "targets": "Government, Diplomatic, Technology",
        "relevance": "SolarWinds supply chain attack. Persistent targeting of Western government networks.",
        "mitre_id": "G0016",
        "active": True,
    },
    {
        "name": "Sandworm (Voodoo Bear)",
        "attribution": "Russia / GRU Unit 74455",
        "targets": "Critical Infrastructure, Energy, Government",
        "relevance": "Destructive attacks on critical infrastructure. NotPetya, Industroyer operations.",
        "mitre_id": "G0034",
        "active": True,
    },
    {
        "name": "SideWinder",
        "attribution": "India (suspected)",
        "targets": "Government, Military (Pakistan, China, SE Asia)",
        "relevance": "Active in APAC region targeting government and military entities.",
        "mitre_id": "G0121",
        "active": True,
    },
]

# Australian cyber policy reference data
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


def fetch_aspi_feed() -> list[dict]:
    """Fetch ASPI strategic analysis RSS feed."""
    logger.info("Fetching ASPI strategic feed...")
    entries = []

    try:
        resp = fetch_url(SOURCES["aspi_rss"])
        if resp:
            feed = feedparser.parse(resp.content)
            for entry in feed.entries[:30]:
                # Filter for cyber-relevant articles
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

                # Filter for APAC or Australia relevance, or major global threats
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
    aspi = fetch_aspi_feed()
    bleeping = fetch_bleeping_computer()
    all_news = aspi + bleeping
    all_news.sort(key=lambda x: x.get("published", ""), reverse=True)

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "threat_actors": APAC_THREAT_ACTORS,
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
