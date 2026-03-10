"""
Configuration for the Australian Cyber Threat Landscape data pipeline.
API keys are read from environment variables for security.
"""
import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
DOCS_DIR = PROJECT_ROOT / "docs"
DATA_DIR = DOCS_DIR / "assets" / "data"
IMAGES_DIR = DOCS_DIR / "assets" / "images"

# Ensure data directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
IMAGES_DIR.mkdir(parents=True, exist_ok=True)

# API Keys (optional, from environment variables)
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY", "")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Data source URLs
SOURCES = {
    # ASD / ACSC
    "acsc_alerts_rss": "https://www.cyber.gov.au/rss/alerts",
    "acsc_advisories_rss": "https://www.cyber.gov.au/rss/advisories",

    # CISA
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cisa_alerts_rss": "https://www.cisa.gov/cybersecurity-advisories/all.xml",

    # NVD / CVE
    "nvd_cve_api": "https://services.nvd.nist.gov/rest/json/cves/2.0",

    # abuse.ch
    "urlhaus_recent": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    "threatfox_iocs": "https://threatfox-api.abuse.ch/api/v1/",
    "malwarebazaar_recent": "https://mb-api.abuse.ch/api/v1/",

    # AlienVault OTX
    "otx_pulses": "https://otx.alienvault.com/api/v1/pulses/subscribed",

    # GreyNoise
    "greynoise_trends": "https://api.greynoise.io/v3/trends/ips",

    # OAIC Notifiable Data Breaches
    "oaic_ndb": "https://www.oaic.gov.au/privacy/notifiable-data-breaches",

    # AusCERT
    "auscert_rss": "https://portal.auscert.org.au/rss/bulletins/",

    # MITRE ATT&CK
    "mitre_attack_enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",

    # Geopolitical / OSINT
    "aspi_rss": "https://www.aspi.org.au/feed",
    "bom_cyber_news": "https://www.bleepingcomputer.com/feed/",
}

# Request settings
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {
    "User-Agent": "CyberLandscapeAU/1.0 (Automated Threat Intelligence Aggregator)"
}

# Data retention (days)
MAX_DATA_AGE_DAYS = 90
