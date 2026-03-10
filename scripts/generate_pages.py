"""
Generate MkDocs markdown pages from fetched data.
Each page is templated from JSON data files using Jinja2.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, BaseLoader

from .config import DOCS_DIR, DATA_DIR
from .utils import logger, load_data


env = Environment(loader=BaseLoader(), autoescape=False)
env.filters["truncate"] = lambda s, n=200: (s[:n-3] + "...") if len(s) > n else s


def write_page(rel_path: str, content: str):
    """Write a markdown page to docs directory."""
    filepath = DOCS_DIR / rel_path
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(content, encoding="utf-8")
    logger.info(f"  Generated: {rel_path}")


def _build_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Dashboard Home (index.md)
# ---------------------------------------------------------------------------
def generate_index():
    advisories = load_data("advisories.json") or {}
    vulns = load_data("vulnerabilities.json") or {}
    threats = load_data("threats.json") or {}
    osint = load_data("osint.json") or {}
    geo = load_data("geopolitical.json") or {}
    ndb = load_data("ndb.json") or {}

    kev = vulns.get("kev", {})
    recent_cves = vulns.get("recent_cves", {})
    analysis = threats.get("analysis", {})
    otx = osint.get("otx_analysis", {})

    # Pre-compute values to avoid f-string issues with nested dicts
    advisory_count = advisories.get("total_count", 0)
    kev_total = kev.get("total_kev", 0)
    threatfox_total = analysis.get("threatfox", {}).get("total", 0)
    otx_total = otx.get("total_pulses", 0)

    # Top 5 advisories
    top_advisories = advisories.get("advisories", [])[:5]
    adv_rows = ""
    for a in top_advisories:
        adv_rows += f"| [{a['title'][:60]}]({a['link']}) | {a['source']} | {a.get('published', '')[:16]} |\n"

    # Top 5 critical CVEs
    critical = recent_cves.get("critical", [])[:5]
    cve_rows = ""
    for c in critical:
        cve_rows += f"| **{c['id']}** | {c.get('cvss_score', 'N/A')} | {c.get('description', '')[:80]}... |\n"

    # NDB trend
    ndb_trend = ndb.get("trend_summary", [])[:4]
    ndb_rows = ""
    for t in ndb_trend:
        ndb_rows += f"| {t['period']} | {t['total']} | {t['malicious']} | {t['human_error']} |\n"

    # Top threat actors
    actors = geo.get("threat_actors", [])[:5]
    actor_rows = ""
    for a in actors:
        status = ":material-alert-circle:{ .active }" if a.get("active") else ""
        actor_rows += f"| **{a['name']}** | {a['attribution']} | {a['targets'][:40]} | {status} |\n"

    content = f"""---
hide:
  - navigation
---

# :material-shield-alert: Australian Cyber Threat Landscape

<div class="dashboard-meta" markdown>
**Last updated:** {_build_timestamp()} | **Auto-generated from live intelligence feeds**
</div>

---

## At a Glance

<div class="grid cards" markdown>

-   :material-alert-decagram:{{ .lg .middle }} **{advisory_count}**

    ---

    Active Advisories (ACSC, AusCERT, CISA)

    [:octicons-arrow-right-24: View advisories](threats/advisories.md)

-   :material-bug:{{ .lg .middle }} **{kev_total}**

    ---

    CISA Known Exploited Vulnerabilities

    [:octicons-arrow-right-24: View vulnerabilities](threats/vulnerabilities.md)

-   :material-virus:{{ .lg .middle }} **{threatfox_total}**

    ---

    Recent ThreatFox IOCs (7 days)

    [:octicons-arrow-right-24: View threat feeds](threats/malware.md)

-   :material-earth:{{ .lg .middle }} **{otx_total}**

    ---

    OTX Threat Intelligence Pulses

    [:octicons-arrow-right-24: View OSINT](osint/index.md)

</div>

---

## :material-bell-alert: Latest Advisories

| Advisory | Source | Date |
|----------|--------|------|
{adv_rows}

[:octicons-arrow-right-24: All advisories](threats/advisories.md){{ .md-button }}

---

## :material-bug: Critical Vulnerabilities (Last 14 Days)

| CVE ID | CVSS | Description |
|--------|------|-------------|
{cve_rows}

[:octicons-arrow-right-24: Full vulnerability report](threats/vulnerabilities.md){{ .md-button }}

---

## :material-account-alert: Key APAC Threat Actors

| Actor | Attribution | Primary Targets | Active |
|-------|-------------|----------------|--------|
{actor_rows}

[:octicons-arrow-right-24: Full threat actor profiles](geopolitical/apac-threats.md){{ .md-button }}

---

## :material-chart-line: Australian Data Breach Trends (OAIC NDB)

| Period | Total | Malicious Attacks | Human Error |
|--------|-------|-------------------|-------------|
{ndb_rows}

<canvas id="ndbTrendChart" width="800" height="300"></canvas>

[:octicons-arrow-right-24: Full NDB analysis](compliance/ndb-stats.md){{ .md-button }}

---

## :material-rss: Geopolitical & Strategic News

"""
    news = geo.get("news", [])[:8]
    for n in news:
        content += f"- [{n['title']}]({n['link']}) *({n['source']}, {n.get('published', '')[:16]})*\n"

    content += f"""
[:octicons-arrow-right-24: All geopolitical intelligence](geopolitical/index.md){{ .md-button }}

---

<div class="data-sources-footer" markdown>
**Data sources:** ASD/ACSC | AusCERT | CISA | NVD | abuse.ch (URLhaus, ThreatFox, MalwareBazaar) | AlienVault OTX | OAIC | ASPI | BleepingComputer

[:octicons-arrow-right-24: View all data sources and methodology](sources.md)
</div>
"""

    write_page("index.md", content)


# ---------------------------------------------------------------------------
# Threats section
# ---------------------------------------------------------------------------
def generate_threats_index():
    advisories = load_data("advisories.json") or {}
    vulns = load_data("vulnerabilities.json") or {}
    threats = load_data("threats.json") or {}

    content = f"""# :material-shield-alert: Threat Intelligence Overview

**Last updated:** {_build_timestamp()}

This section aggregates threat intelligence from Australian and international sources, providing a consolidated view of the current cyber threat environment relevant to Australia.

## Data Sources

| Source | Type | Coverage |
|--------|------|----------|
| ASD/ACSC | Government advisories | Australian-specific alerts and guidance |
| AusCERT | CERT advisories | Australian security bulletins |
| CISA | US Government advisories | Global vulnerability and threat advisories |
| NVD | Vulnerability database | CVE details with CVSS scoring |
| CISA KEV | Exploited vulnerabilities | Confirmed actively exploited CVEs |
| abuse.ch | Threat feeds | URLhaus, ThreatFox, MalwareBazaar |

## Current Summary

- **{advisories.get('total_count', 0)}** active advisories across all sources
- **{vulns.get('kev', {}).get('recent_30d', 0)}** new KEV entries in the last 30 days
- **{vulns.get('recent_cves', {}).get('total', 0)}** new CVEs published in the last 14 days
- **{threats.get('analysis', {}).get('urlhaus', {}).get('total', 0)}** recent malicious URLs tracked

## Sections

- [ACSC & CISA Advisories](advisories.md) : Government alerts and security advisories
- [Vulnerabilities & KEV](vulnerabilities.md) : CVE tracking and exploited vulnerability catalog
- [Malware & Threat Feeds](malware.md) : abuse.ch intelligence feeds
"""
    write_page("threats/index.md", content)


def generate_advisories_page():
    data = load_data("advisories.json") or {}
    advisories = data.get("advisories", [])
    by_source = data.get("by_source", {})

    content = f"""# :material-bell-alert: Security Advisories

**Last updated:** {_build_timestamp()} | **Total: {data.get('total_count', 0)} advisories**

## Sources

| Source | Count |
|--------|-------|
"""
    for source, count in by_source.items():
        content += f"| {source} | {count} |\n"

    # Group by source
    for source in ["ACSC Alerts", "ACSC Advisories", "AusCERT", "CISA"]:
        source_items = [a for a in advisories if a["source"] == source]
        if not source_items:
            continue

        content += f"\n## {source}\n\n"
        content += "| Date | Advisory | Summary |\n|------|----------|--------|\n"
        for a in source_items[:25]:
            date = a.get("published", "")[:16]
            title = a["title"][:70]
            summary = a.get("summary", "")[:100].replace("|", " ").replace("\n", " ")
            content += f"| {date} | [{title}]({a['link']}) | {summary} |\n"

    write_page("threats/advisories.md", content)


def generate_vulnerabilities_page():
    data = load_data("vulnerabilities.json") or {}
    kev = data.get("kev", {})
    cves = data.get("recent_cves", {})

    content = f"""# :material-bug: Vulnerabilities & Known Exploited Vulnerabilities

**Last updated:** {_build_timestamp()}

## CISA Known Exploited Vulnerabilities (KEV)

The KEV catalog tracks vulnerabilities confirmed to be actively exploited in the wild.

| Metric | Value |
|--------|-------|
| Total KEV entries | **{kev.get('total_kev', 0)}** |
| Added in last 30 days | **{kev.get('recent_30d', 0)}** |
| Overdue remediations | **{kev.get('overdue_count', 0)}** |

### Top Affected Vendors (KEV)

<canvas id="kevVendorChart" width="800" height="400"></canvas>

| Vendor | Exploited CVEs |
|--------|---------------|
"""
    for v in kev.get("top_vendors", [])[:15]:
        content += f"| {v['vendor']} | {v['count']} |\n"

    content += f"""
### Recently Added to KEV (Last 30 Days)

| CVE | Vendor | Product | Date Added | Due Date |
|-----|--------|---------|------------|----------|
"""
    for v in kev.get("recent_entries", [])[:20]:
        content += f"| {v.get('cveID', '')} | {v.get('vendorProject', '')} | {v.get('product', '')} | {v.get('dateAdded', '')} | {v.get('dueDate', '')} |\n"

    # Recent CVEs section
    severity = cves.get("severity_distribution", {})
    content += f"""
---

## Recent CVEs (Last 14 Days)

**Total new CVEs:** {cves.get('total', 0)}

### Severity Distribution

<canvas id="cveSeverityChart" width="400" height="300"></canvas>

| Severity | Count |
|----------|-------|
"""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in severity:
            content += f"| {sev} | {severity[sev]} |\n"

    content += """
### Critical CVEs (CVSS >= 9.0)

| CVE ID | CVSS | Description |
|--------|------|-------------|
"""
    for c in cves.get("critical", [])[:20]:
        desc = c.get("description", "")[:120].replace("|", " ").replace("\n", " ")
        content += f"| **{c['id']}** | {c.get('cvss_score', 'N/A')} | {desc} |\n"

    write_page("threats/vulnerabilities.md", content)


def generate_malware_page():
    data = load_data("threats.json") or {}
    analysis = data.get("analysis", {})

    content = f"""# :material-virus: Malware & Threat Feeds

**Last updated:** {_build_timestamp()}

Data sourced from [abuse.ch](https://abuse.ch/) community threat intelligence platforms.

## URLhaus : Malicious URLs

**Recent URLs tracked:** {analysis.get('urlhaus', {}).get('total', 0)}

### Threat Types

<canvas id="urlhausThreatChart" width="600" height="300"></canvas>

| Threat Type | Count |
|-------------|-------|
"""
    for threat, count in analysis.get("urlhaus", {}).get("threat_types", {}).items():
        content += f"| {threat} | {count} |\n"

    content += f"""
---

## ThreatFox : Indicators of Compromise

**Recent IOCs (7 days):** {analysis.get('threatfox', {}).get('total', 0)}

### Top Malware Families

| Malware Family | IOC Count |
|---------------|-----------|
"""
    for mal, count in analysis.get("threatfox", {}).get("top_malware", {}).items():
        content += f"| {mal} | {count} |\n"

    content += """
### IOC Types

| Type | Count |
|------|-------|
"""
    for ioc_type, count in analysis.get("threatfox", {}).get("ioc_types", {}).items():
        content += f"| {ioc_type} | {count} |\n"

    content += f"""
---

## MalwareBazaar : Malware Samples

**Recent samples:** {analysis.get('malwarebazaar', {}).get('total', 0)}

### File Types

<canvas id="malwareFileTypeChart" width="600" height="300"></canvas>

| File Type | Count |
|-----------|-------|
"""
    for ft, count in analysis.get("malwarebazaar", {}).get("file_types", {}).items():
        content += f"| {ft} | {count} |\n"

    content += """
### Top Malware Signatures

| Signature | Samples |
|-----------|---------|
"""
    for sig, count in analysis.get("malwarebazaar", {}).get("top_signatures", {}).items():
        content += f"| {sig} | {count} |\n"

    content += """
---

## Trending Tags (All Sources)

| Tag | Mentions |
|-----|----------|
"""
    for t in analysis.get("top_tags", [])[:20]:
        content += f"| `{t['tag']}` | {t['count']} |\n"

    write_page("threats/malware.md", content)


# ---------------------------------------------------------------------------
# OSINT section
# ---------------------------------------------------------------------------
def generate_osint_index():
    data = load_data("osint.json") or {}
    otx = data.get("otx_analysis", {})

    content = f"""# :material-earth: OSINT Intelligence

**Last updated:** {_build_timestamp()}

Open-source intelligence aggregated from community threat intelligence platforms and internet scanning services.

## AlienVault OTX Summary

| Metric | Value |
|--------|-------|
| Total pulses analysed | **{otx.get('total_pulses', 0)}** |
| Australia-relevant pulses | **{otx.get('australia_relevant_count', 0)}** |
| Unique threat actors identified | **{len(otx.get('adversaries', []))}** |
| Unique malware families | **{len(otx.get('malware_families', []))}** |

### Top Targeted Countries

<canvas id="otxCountryChart" width="600" height="300"></canvas>

| Country | Pulse Count |
|---------|-------------|
"""
    for c in otx.get("targeted_countries", [])[:15]:
        flag = ":flag_au:" if c["country"] == "AU" else ""
        content += f"| {c['country']} {flag} | {c['count']} |\n"

    content += """
### Top ATT&CK Techniques Observed

| Technique | Occurrences |
|-----------|-------------|
"""
    for t in otx.get("attack_techniques", [])[:15]:
        content += f"| {t['technique']} | {t['count']} |\n"

    content += """
### Top Intelligence Tags

| Tag | Count |
|-----|-------|
"""
    for t in otx.get("top_tags", [])[:15]:
        content += f"| `{t['tag']}` | {t['count']} |\n"

    content += """
## Sections

- [Internet Exposure](exposure.md) : GreyNoise scanning trends and internet-facing asset analysis
- [Indicators of Compromise](iocs.md) : Consolidated IOCs from OTX pulses
"""
    write_page("osint/index.md", content)


def generate_exposure_page():
    data = load_data("osint.json") or {}
    greynoise = data.get("greynoise", {})
    shodan_data = load_data("shodan.json") or {}
    shodan = shodan_data.get("shodan", {})

    content = f"""# :material-access-point-network: Internet Exposure & Scanning Trends

**Last updated:** {_build_timestamp()}

## :material-radar: Shodan: Australian Internet Exposure

"""
    if shodan.get("available"):
        au_total = shodan.get("au_total_hosts", 0)
        content += f"**Total Australian hosts indexed:** {au_total:,}\n\n"

        exposure = shodan.get("exposure_results", [])
        if exposure:
            content += """<canvas id="shodanExposureChart" width="800" height="400"></canvas>

| Service | Query | Exposed Hosts |
|---------|-------|---------------|
"""
            for e in exposure:
                count = e.get("count", 0)
                content += f"| {e['name']} | `{e['query']}` | **{count:,}** |\n"

        credits = shodan.get("api_credits", {})
        content += f"""
!!! info "Shodan API Status"
    Query credits remaining: **{credits.get('query', 'N/A')}** | Scan credits: **{credits.get('scan', 'N/A')}**
"""
    else:
        content += """!!! info "API Key Required"
    Set the `SHODAN_API_KEY` environment variable (or GitHub Secret) to enable live Shodan data.
    See the [API Key Setup Guide](../sources.md#api-key-setup-guide) for details.

"""

    content += """
---

## GreyNoise Internet Scanner Trends

"""
    if greynoise.get("available") is False:
        content += """!!! info "API Key Required"
    Set the `GREYNOISE_API_KEY` environment variable to enable live GreyNoise data.
    See the [API Key Setup Guide](../sources.md#api-key-setup-guide) for details.

GreyNoise classifies internet-wide scanning traffic as either **benign** (known security scanners, search engines) or **malicious/unknown** (botnets, exploit scanners, reconnaissance).

When enabled, this section shows top scanning ports, scanner classifications, geographic distribution, and trending CVE exploitation.
"""
    else:
        content += "GreyNoise data is available. See charts below.\n\n"
        content += f"```json\n{json.dumps(greynoise, indent=2)[:2000]}\n```\n"

    content += """
---

## Recommended OSINT Tools for Australian Practitioners

| Tool | Type | Access |
|------|------|--------|
| [Shodan](https://www.shodan.io/) | Internet-facing device search | Free tier + paid |
| [Censys](https://search.censys.io/) | Internet asset discovery | Free tier + paid |
| [GreyNoise](https://viz.greynoise.io/) | Internet scanning analysis | Free community |
| [SecurityTrails](https://securitytrails.com/) | DNS and domain intelligence | Free tier + paid |
| [URLScan.io](https://urlscan.io/) | Website scanning and analysis | Free |
| [VirusTotal](https://www.virustotal.com/) | File and URL analysis | Free tier + paid |
| [AbuseIPDB](https://www.abuseipdb.com/) | IP reputation checking | Free tier + paid |
"""
    write_page("osint/exposure.md", content)


def generate_iocs_page():
    data = load_data("osint.json") or {}
    pulses = data.get("otx_pulses", [])
    otx = data.get("otx_analysis", {})

    content = f"""# :material-fingerprint: Indicators of Compromise

**Last updated:** {_build_timestamp()}

## Australia-Relevant Threat Pulses

"""
    au_relevant = otx.get("australia_relevant", [])
    if au_relevant:
        content += "| Pulse | Adversary | Tags | Indicators |\n|-------|-----------|------|------------|\n"
        for p in au_relevant[:10]:
            tags = ", ".join(p.get("tags", [])[:5])
            content += f"| {p['name'][:50]} | {p.get('adversary', 'N/A')} | {tags} | {p.get('indicator_count', 0)} |\n"
    else:
        content += "No specifically Australia-targeted pulses in the current dataset.\n"

    content += """
## Recent OTX Pulses (All Regions)

| Pulse Name | Created | Tags | Indicators |
|------------|---------|------|------------|
"""
    for p in pulses[:25]:
        tags = ", ".join(p.get("tags", [])[:4])
        created = p.get("created", "")[:10]
        content += f"| {p['name'][:60]} | {created} | {tags} | {p.get('indicator_count', 0)} |\n"

    content += """
## Top Malware Families (OTX)

| Family | Occurrences |
|--------|-------------|
"""
    for m in otx.get("malware_families", [])[:15]:
        content += f"| {m['family']} | {m['count']} |\n"

    content += """
## Known Adversaries (OTX)

| Threat Actor | Pulse Count |
|-------------|-------------|
"""
    for a in otx.get("adversaries", [])[:10]:
        content += f"| {a['name']} | {a['count']} |\n"

    write_page("osint/iocs.md", content)


# ---------------------------------------------------------------------------
# Geopolitical section
# ---------------------------------------------------------------------------
def generate_geopolitical_index():
    data = load_data("geopolitical.json") or {}
    news = data.get("news", [])

    content = f"""# :material-earth: Geopolitical Cyber Intelligence

**Last updated:** {_build_timestamp()}

Strategic cyber intelligence relevant to Australia's geopolitical position in the Indo-Pacific region.

## Latest Strategic & Cyber News

"""
    for n in news[:15]:
        content += f"- [{n['title']}]({n['link']}) *({n['source']}, {n.get('published', '')[:16]})*\n"

    content += """
## Sections

- [APAC Threat Actors](apac-threats.md) : State-sponsored and advanced threat groups targeting Australia and the Indo-Pacific
- [Cyber Policy & Sanctions](policy.md) : Australian cyber legislation and international policy frameworks
"""
    write_page("geopolitical/index.md", content)


def generate_apac_threats_page():
    data = load_data("geopolitical.json") or {}
    actors = data.get("threat_actors", [])

    content = f"""# :material-account-alert: APAC Threat Actors

**Last updated:** {_build_timestamp()}

State-sponsored and advanced persistent threat (APT) groups with known activity targeting Australia, the Indo-Pacific, and Five Eyes nations.

!!! warning "Classification Note"
    Attribution of cyber operations to specific nation-states is inherently complex. The attributions listed here reflect publicly available reporting from government agencies and reputable threat intelligence firms.

"""
    # Group by attribution country
    by_country = {}
    for a in actors:
        country = a["attribution"].split("/")[0].split("(")[0].strip()
        by_country.setdefault(country, []).append(a)

    for country, group in by_country.items():
        content += f"## {country}\n\n"
        for a in group:
            mitre_link = f" | [MITRE ATT&CK](https://attack.mitre.org/groups/{a['mitre_id']}/)" if a.get("mitre_id") else ""
            status = ":material-alert-circle:{{ style='color: #ff5252' }} **Active**" if a.get("active") else "Inactive"

            content += f"""### {a['name']}

| | |
|---|---|
| **Attribution** | {a['attribution']} |
| **Status** | {status} |
| **Primary Targets** | {a['targets']} |
| **Australia Relevance** | {a['relevance']} |
| **References** | {mitre_link} |

---

"""

    write_page("geopolitical/apac-threats.md", content)


def generate_policy_page():
    data = load_data("geopolitical.json") or {}
    policies = data.get("au_cyber_policy", [])

    content = f"""# :material-gavel: Australian Cyber Policy & Legislation

**Last updated:** {_build_timestamp()}

Key legislative and policy frameworks governing cybersecurity in Australia.

"""
    for p in policies:
        content += f"""## {p['name']}

| | |
|---|---|
| **Status** | {p['status']} |
| **Scope** | {p['scope']} |
| **Key Requirements** | {p['key_requirements']} |
| **Reference** | [{p['name']}]({p['link']}) |

---

"""

    content += """## International Frameworks

Australia participates in several international cyber cooperation frameworks:

| Framework | Partners | Focus |
|-----------|----------|-------|
| Five Eyes | AU, US, UK, CA, NZ | Intelligence sharing, joint advisories |
| AUKUS Pillar II | AU, UK, US | Advanced cyber capabilities, quantum, AI |
| Quad Cyber | AU, US, India, Japan | Indo-Pacific cyber resilience |
| ASEAN Regional Forum | ASEAN + partners | Regional cyber confidence building |
| Budapest Convention | 60+ countries | Cybercrime cooperation |
"""
    write_page("geopolitical/policy.md", content)


# ---------------------------------------------------------------------------
# Compliance section
# ---------------------------------------------------------------------------
def generate_compliance_index():
    content = f"""# :material-clipboard-check: Australian Compliance & Regulation

**Last updated:** {_build_timestamp()}

Cybersecurity compliance landscape for Australian organisations, including mandated frameworks and breach reporting obligations.

## Sections

- [Essential Eight](essential-eight.md) : ASD's Essential Eight mitigation strategies and maturity model
- [Notifiable Data Breaches](ndb-stats.md) : OAIC NDB statistics and trend analysis
"""
    write_page("compliance/index.md", content)


def generate_essential_eight_page():
    content = f"""# :material-shield-check: ASD Essential Eight Maturity Model

**Last updated:** {_build_timestamp()}

The [Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) is a set of baseline mitigation strategies from the Australian Signals Directorate (ASD), recommended for all Australian organisations and mandated for Commonwealth entities.

## The Eight Strategies

### Prevent Malware Delivery and Execution

| # | Strategy | Purpose |
|---|----------|---------|
| 1 | **Application Control** | Prevent execution of unapproved/malicious programs |
| 2 | **Patch Applications** | Remediate known application vulnerabilities |
| 3 | **Configure Microsoft Office Macros** | Block macros from the internet, only allow vetted macros |
| 4 | **User Application Hardening** | Block ads, Java, Flash, and unnecessary features in browsers |

### Limit Extent of Cyber Incidents

| # | Strategy | Purpose |
|---|----------|---------|
| 5 | **Restrict Administrative Privileges** | Limit admin access to only those who need it |
| 6 | **Patch Operating Systems** | Remediate known OS vulnerabilities |
| 7 | **Multi-factor Authentication** | Protect against credential theft and reuse |

### Recover Data and System Availability

| # | Strategy | Purpose |
|---|----------|---------|
| 8 | **Regular Backups** | Ensure data and systems can be recovered |

## Maturity Levels

| Level | Description |
|-------|-------------|
| **Maturity Level Zero** | Weaknesses in overall cyber security posture |
| **Maturity Level One** | Partly aligned, focus on adversaries using commodity tradecraft |
| **Maturity Level Two** | Aligned to mitigate adversaries operating with moderate investment |
| **Maturity Level Three** | Fully aligned, mitigates adversaries who are more adaptive and less reliant on public tooling |

!!! tip "Assessment"
    Organisations can self-assess their Essential Eight maturity using the [Essential Eight Assessment Process Guide](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-assessment-process-guide).

## Key Updates

- **November 2023**: Updated to include revised maturity levels and control requirements
- **Mandated**: All non-corporate Commonwealth entities must implement to at least Maturity Level Two
- **PSPF Alignment**: Maps to the Protective Security Policy Framework (PSPF) requirements
"""
    write_page("compliance/essential-eight.md", content)


def generate_ndb_page():
    data = load_data("ndb.json") or {}
    trend = data.get("trend_summary", [])
    breaches = data.get("notable_breaches", [])
    periods = data.get("detailed_periods", [])

    content = f"""# :material-database-alert: Notifiable Data Breaches (OAIC)

**Last updated:** {_build_timestamp()}

Statistics from the [Office of the Australian Information Commissioner](https://www.oaic.gov.au/privacy/notifiable-data-breaches) Notifiable Data Breaches (NDB) scheme.

## Trend Overview

<canvas id="ndbDetailChart" width="800" height="400"></canvas>

| Period | Total | Malicious Attacks | Human Error | System Faults |
|--------|-------|-------------------|-------------|---------------|
"""
    for t in trend:
        content += f"| {t['period']} | **{t['total']}** | {t['malicious']} | {t['human_error']} | {t['system_faults']} |\n"

    # Detailed breakdown for most recent period
    if periods:
        latest = periods[0]
        content += f"""
## Latest Period: {latest['period']}

### Top Affected Sectors

<canvas id="ndbSectorChart" width="600" height="300"></canvas>

| Sector | Notifications |
|--------|--------------|
"""
        for s in latest.get("top_sectors", []):
            content += f"| {s['sector']} | {s['count']} |\n"

        if "breach_types" in latest:
            content += """
### Breach Types

| Type | Count |
|------|-------|
"""
            for bt, count in latest["breach_types"].items():
                label = bt.replace("_", " ").title()
                content += f"| {label} | {count} |\n"

        if "individuals_affected" in latest:
            content += """
### Scale of Breaches (Individuals Affected)

| Range | Notifications |
|-------|--------------|
"""
            for range_str, count in latest["individuals_affected"].items():
                content += f"| {range_str} | {count} |\n"

    content += """
---

## Notable Australian Data Breaches

| Entity | Date | Records | Attack Type |
|--------|------|---------|-------------|
"""
    for b in breaches:
        content += f"| **{b['entity']}** | {b['date']} | {b['records_affected']} | {b['attack_type']} |\n"

    content += f"""
---

*Data sourced from [OAIC NDB publications]({data.get('source_url', '#')}). Updated when new OAIC reports are published.*
"""
    write_page("compliance/ndb-stats.md", content)


# ---------------------------------------------------------------------------
# Sources page
# ---------------------------------------------------------------------------
def generate_sources_page():
    content = f"""# :material-database: Data Sources & Methodology

**Last updated:** {_build_timestamp()}

## How This Dashboard Works

This dashboard is automatically generated by a Python data pipeline that:

1. **Fetches** data from multiple threat intelligence sources via APIs and RSS feeds
2. **Processes** and analyses the raw data to extract key metrics and trends
3. **Generates** MkDocs markdown pages with embedded data and chart configurations
4. **Builds** the static site using MkDocs with the Material theme
5. **Deploys** to GitHub Pages via GitHub Actions

The pipeline runs on a scheduled basis (configurable via GitHub Actions cron) to keep data current.

## Data Sources

### Australian Government

| Source | Type | URL | Update Frequency |
|--------|------|-----|-----------------|
| ASD/ACSC Alerts | RSS Feed | [cyber.gov.au](https://www.cyber.gov.au/) | As published |
| ASD/ACSC Advisories | RSS Feed | [cyber.gov.au](https://www.cyber.gov.au/) | As published |
| AusCERT Bulletins | RSS Feed | [auscert.org.au](https://www.auscert.org.au/) | As published |
| OAIC NDB Reports | Curated data | [oaic.gov.au](https://www.oaic.gov.au/) | Bi-annual |

### International Government

| Source | Type | URL | Update Frequency |
|--------|------|-----|-----------------|
| CISA Advisories | RSS Feed | [cisa.gov](https://www.cisa.gov/) | As published |
| CISA KEV Catalog | JSON API | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | As updated |
| NVD (CVE Database) | REST API | [nvd.nist.gov](https://nvd.nist.gov/) | Continuous |

### Community Threat Intelligence

| Source | Type | URL | Update Frequency |
|--------|------|-----|-----------------|
| abuse.ch URLhaus | REST API | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/) | Real-time |
| abuse.ch ThreatFox | REST API | [threatfox.abuse.ch](https://threatfox.abuse.ch/) | Real-time |
| abuse.ch MalwareBazaar | REST API | [bazaar.abuse.ch](https://bazaar.abuse.ch/) | Real-time |
| AlienVault OTX | REST API | [otx.alienvault.com](https://otx.alienvault.com/) | Real-time |

### Strategic & Geopolitical

| Source | Type | URL | Update Frequency |
|--------|------|-----|-----------------|
| ASPI (The Strategist) | RSS Feed | [aspi.org.au](https://www.aspi.org.au/) | As published |
| BleepingComputer | RSS Feed | [bleepingcomputer.com](https://www.bleepingcomputer.com/) | As published |

### Optional (API Key Required)

| Source | Type | URL | Environment Variable |
|--------|------|-----|---------------------|
| NVD | REST API | [nvd.nist.gov](https://nvd.nist.gov/) | `NVD_API_KEY` |
| AlienVault OTX | REST API | [otx.alienvault.com](https://otx.alienvault.com/) | `OTX_API_KEY` |
| GreyNoise | REST API | [greynoise.io](https://www.greynoise.io/) | `GREYNOISE_API_KEY` |
| Shodan | REST API | [shodan.io](https://www.shodan.io/) | `SHODAN_API_KEY` |

## API Key Setup Guide

All API keys are optional. The dashboard will still build without them, but enabling them unlocks richer data. Keys should be stored as **GitHub Secrets** (Settings > Secrets and variables > Actions) for the automated pipeline, or as environment variables for local development.

### NVD (National Vulnerability Database)

The NVD API works without a key, but rate-limits unauthenticated requests to 5 per 30 seconds. With a key, you get 50 per 30 seconds.

1. Go to [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
2. Enter your email address and organisation
3. Check your inbox for the API key (arrives within minutes)
4. **GitHub Secret name:** `NVD_API_KEY`

**Cost:** Free, no usage limits beyond rate throttling.

### AlienVault OTX (Open Threat Exchange)

OTX provides community-sourced threat intelligence pulses, IOCs, and adversary tracking.

1. Go to [https://otx.alienvault.com/](https://otx.alienvault.com/) and create a free account
2. Once logged in, go to **Settings** (click your avatar, top-right)
3. Your API key is displayed under **OTX Key** on the settings page
4. Optionally subscribe to relevant pulses (e.g. search for "Australia", "APT40", "Critical Infrastructure") to get more targeted data
5. **GitHub Secret name:** `OTX_API_KEY`

**Cost:** Free. No usage limits for the public API.

### GreyNoise

GreyNoise classifies internet scanning traffic as benign or malicious. The community tier provides basic IP lookups.

1. Go to [https://viz.greynoise.io/signup](https://viz.greynoise.io/signup) and create a free Community account
2. Once logged in, go to **Account > API Key**
3. Copy the API key
4. **GitHub Secret name:** `GREYNOISE_API_KEY`

**Cost:** Free Community tier (limited queries/day). Paid tiers available for full trend data and bulk lookups.

### Shodan

Shodan indexes internet-facing devices and services globally. Used here to query Australian IP space exposure.

1. Go to [https://account.shodan.io/register](https://account.shodan.io/register) and create an account
2. Once logged in, your API key is shown on the [Account page](https://account.shodan.io/)
3. The free tier provides basic search. A paid membership (one-time USD $49 for lifetime) unlocks filters like `country:AU`
4. **GitHub Secret name:** `SHODAN_API_KEY`

**Cost:** Free tier available. Lifetime membership recommended for country-level queries.

### Adding Secrets to GitHub

In your repository:

1. Go to **Settings > Secrets and variables > Actions**
2. Click **New repository secret**
3. Add each key with the exact name shown above (e.g. `NVD_API_KEY`)
4. The GitHub Actions workflow already references these secrets

## Architecture

```mermaid
graph LR
    A[RSS Feeds] --> D[Python Fetchers]
    B[REST APIs] --> D
    C[Curated Data] --> D
    D --> E[JSON Data Files]
    E --> F[Page Generator]
    F --> G[MkDocs Markdown]
    G --> H[MkDocs Build]
    H --> I[GitHub Pages]
```

## Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Set API keys (optional, enhances data)
export SHODAN_API_KEY="your-key"
export NVD_API_KEY="your-key"
export OTX_API_KEY="your-key"
export GREYNOISE_API_KEY="your-key"

# Fetch data and generate pages
python -m scripts.build_all

# Preview locally
mkdocs serve

# Build static site
mkdocs build
```
"""
    write_page("sources.md", content)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def generate_all_pages():
    """Generate all markdown pages from cached data."""
    logger.info("Generating all pages...")

    generate_index()
    generate_threats_index()
    generate_advisories_page()
    generate_vulnerabilities_page()
    generate_malware_page()
    generate_osint_index()
    generate_exposure_page()
    generate_iocs_page()
    generate_geopolitical_index()
    generate_apac_threats_page()
    generate_policy_page()
    generate_compliance_index()
    generate_essential_eight_page()
    generate_ndb_page()
    generate_sources_page()

    logger.info("All pages generated successfully")


if __name__ == "__main__":
    generate_all_pages()
