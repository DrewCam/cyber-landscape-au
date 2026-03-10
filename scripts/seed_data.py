#!/usr/bin/env python3
"""
Generate seed/sample data for local development and testing.
This populates the data directory with realistic sample data
so the site can be built without network access.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from .config import DATA_DIR
from .utils import save_data


def seed_advisories():
    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_count": 15,
        "by_source": {"ACSC Alerts": 5, "AusCERT": 5, "CISA": 5},
        "advisories": [
            {"title": "Critical vulnerability in Fortinet FortiOS", "link": "https://www.cyber.gov.au/", "published": "2026-03-08T10:00:00Z", "summary": "ASD is aware of active exploitation of a critical vulnerability in Fortinet FortiOS.", "source": "ACSC Alerts"},
            {"title": "SonicWall SMA appliances actively exploited", "link": "https://www.cyber.gov.au/", "published": "2026-03-06T08:00:00Z", "summary": "Multiple vulnerabilities in SonicWall SMA 100 series appliances are being actively exploited.", "source": "ACSC Alerts"},
            {"title": "Essential Eight update: MFA requirements strengthened", "link": "https://www.cyber.gov.au/", "published": "2026-03-04T09:00:00Z", "summary": "Updated guidance on multi-factor authentication requirements under the Essential Eight.", "source": "ACSC Alerts"},
            {"title": "Advisory on PRC-linked cyber actors targeting telcos", "link": "https://www.cyber.gov.au/", "published": "2026-03-01T11:00:00Z", "summary": "Joint advisory on PRC-affiliated threat actors targeting telecommunications providers.", "source": "ACSC Alerts"},
            {"title": "Ivanti Connect Secure exploitation guidance", "link": "https://www.cyber.gov.au/", "published": "2026-02-28T14:00:00Z", "summary": "Guidance on detecting and mitigating exploitation of Ivanti Connect Secure appliances.", "source": "ACSC Alerts"},
            {"title": "ESB-2026.0312 - Apache Tomcat RCE vulnerability", "link": "https://www.auscert.org.au/", "published": "2026-03-09T06:00:00Z", "summary": "Critical remote code execution vulnerability in Apache Tomcat (CVE-2026-XXXX).", "source": "AusCERT"},
            {"title": "ESB-2026.0298 - Microsoft Exchange Server updates", "link": "https://www.auscert.org.au/", "published": "2026-03-07T05:00:00Z", "summary": "Security updates addressing multiple vulnerabilities in Microsoft Exchange Server.", "source": "AusCERT"},
            {"title": "ESB-2026.0285 - Cisco IOS XE privilege escalation", "link": "https://www.auscert.org.au/", "published": "2026-03-05T07:00:00Z", "summary": "Privilege escalation vulnerability in Cisco IOS XE web UI.", "source": "AusCERT"},
            {"title": "ESB-2026.0271 - VMware vCenter Server critical patch", "link": "https://www.auscert.org.au/", "published": "2026-03-03T04:00:00Z", "summary": "Critical authentication bypass in VMware vCenter Server.", "source": "AusCERT"},
            {"title": "ESB-2026.0258 - Palo Alto PAN-OS command injection", "link": "https://www.auscert.org.au/", "published": "2026-03-01T06:00:00Z", "summary": "Command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect.", "source": "AusCERT"},
            {"title": "CISA Adds Three Known Exploited Vulnerabilities to Catalog", "link": "https://www.cisa.gov/", "published": "2026-03-09T15:00:00Z", "summary": "CISA has added three new vulnerabilities to its Known Exploited Vulnerabilities Catalog.", "source": "CISA"},
            {"title": "Threat Actors Exploit Multiple ICS/SCADA Vulnerabilities", "link": "https://www.cisa.gov/", "published": "2026-03-07T12:00:00Z", "summary": "Multiple threat actors exploiting vulnerabilities in industrial control systems.", "source": "CISA"},
            {"title": "AA26-065A: PRC State-Sponsored Cyber Actors Target Critical Infrastructure", "link": "https://www.cisa.gov/", "published": "2026-03-05T16:00:00Z", "summary": "Joint advisory on PRC-affiliated actors pre-positioning for disruptive operations.", "source": "CISA"},
            {"title": "Ransomware Advisory: Play Group Targeting Healthcare", "link": "https://www.cisa.gov/", "published": "2026-03-03T14:00:00Z", "summary": "Advisory on Play ransomware group activities targeting healthcare sector.", "source": "CISA"},
            {"title": "Updated Best Practices for Securing Cloud Environments", "link": "https://www.cisa.gov/", "published": "2026-03-01T13:00:00Z", "summary": "Updated guidance on securing cloud environments against common attack patterns.", "source": "CISA"},
        ],
    }
    save_data("advisories.json", data)


def seed_vulnerabilities():
    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "kev": {
            "total_kev": 1247,
            "recent_30d": 18,
            "recent_entries": [
                {"cveID": "CVE-2026-1234", "vendorProject": "Fortinet", "product": "FortiOS", "dateAdded": "2026-03-08", "dueDate": "2026-03-29"},
                {"cveID": "CVE-2026-0987", "vendorProject": "SonicWall", "product": "SMA 100", "dateAdded": "2026-03-06", "dueDate": "2026-03-27"},
                {"cveID": "CVE-2025-9876", "vendorProject": "Ivanti", "product": "Connect Secure", "dateAdded": "2026-03-04", "dueDate": "2026-03-25"},
                {"cveID": "CVE-2026-0555", "vendorProject": "Apache", "product": "Tomcat", "dateAdded": "2026-03-02", "dueDate": "2026-03-23"},
                {"cveID": "CVE-2025-8765", "vendorProject": "Cisco", "product": "IOS XE", "dateAdded": "2026-02-28", "dueDate": "2026-03-21"},
            ],
            "top_vendors": [
                {"vendor": "Microsoft", "count": 312}, {"vendor": "Apple", "count": 89},
                {"vendor": "Google", "count": 78}, {"vendor": "Cisco", "count": 67},
                {"vendor": "Adobe", "count": 65}, {"vendor": "Fortinet", "count": 42},
                {"vendor": "Ivanti", "count": 38}, {"vendor": "VMware", "count": 35},
                {"vendor": "Oracle", "count": 31}, {"vendor": "Palo Alto Networks", "count": 28},
                {"vendor": "Apache", "count": 26}, {"vendor": "Citrix", "count": 24},
                {"vendor": "SonicWall", "count": 19}, {"vendor": "Samsung", "count": 17},
                {"vendor": "D-Link", "count": 15},
            ],
            "overdue_count": 42,
        },
        "recent_cves": {
            "total": 847,
            "severity_distribution": {"CRITICAL": 43, "HIGH": 218, "MEDIUM": 389, "LOW": 112, "UNKNOWN": 85},
            "critical": [
                {"id": "CVE-2026-1234", "published": "2026-03-08", "description": "Heap-based buffer overflow in Fortinet FortiOS SSL-VPN allows remote code execution via crafted HTTP requests.", "cvss_score": 9.8, "cvss_severity": "CRITICAL"},
                {"id": "CVE-2026-0987", "published": "2026-03-06", "description": "Authentication bypass in SonicWall SMA 100 series allows unauthenticated attackers to gain admin access.", "cvss_score": 9.8, "cvss_severity": "CRITICAL"},
                {"id": "CVE-2026-0555", "published": "2026-03-02", "description": "Remote code execution in Apache Tomcat via deserialization of untrusted data in session persistence.", "cvss_score": 9.1, "cvss_severity": "CRITICAL"},
                {"id": "CVE-2026-0888", "published": "2026-03-01", "description": "SQL injection in WordPress plugin allowing unauthenticated database access.", "cvss_score": 9.8, "cvss_severity": "CRITICAL"},
                {"id": "CVE-2025-9876", "published": "2026-02-28", "description": "Server-side request forgery in Ivanti Connect Secure allows authenticated admin to access internal services.", "cvss_score": 9.0, "cvss_severity": "CRITICAL"},
            ],
            "all": [],
        },
    }
    save_data("vulnerabilities.json", data)


def seed_threats():
    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "analysis": {
            "urlhaus": {
                "total": 87,
                "threat_types": {"malware_download": 34, "phishing": 28, "cryptomining": 12, "ransomware": 8, "c2": 5},
                "statuses": {"online": 45, "offline": 32, "unknown": 10},
            },
            "threatfox": {
                "total": 156,
                "top_malware": {"AgentTesla": 23, "Remcos": 18, "AsyncRAT": 15, "RedLine": 14, "Formbook": 12, "LockBit": 10, "QakBot": 9, "Emotet": 8, "Cobalt Strike": 7, "IcedID": 6},
                "ioc_types": {"ip:port": 67, "domain": 45, "url": 28, "hash": 16},
            },
            "malwarebazaar": {
                "total": 94,
                "file_types": {"exe": 28, "dll": 22, "doc": 15, "docx": 10, "xls": 8, "zip": 6, "iso": 3, "vbs": 2},
                "top_signatures": {"AgentTesla": 15, "Remcos": 12, "AsyncRAT": 9, "RedLine": 8, "Formbook": 7, "LockBit3": 6, "QakBot": 5},
            },
            "top_tags": [
                {"tag": "AgentTesla", "count": 38}, {"tag": "Remcos", "count": 30},
                {"tag": "exe", "count": 28}, {"tag": "phishing", "count": 28},
                {"tag": "AsyncRAT", "count": 24}, {"tag": "RedLine", "count": 22},
                {"tag": "ransomware", "count": 18}, {"tag": "Formbook", "count": 17},
                {"tag": "LockBit", "count": 16}, {"tag": "CobaltStrike", "count": 14},
            ],
        },
        "urlhaus_urls": [],
        "threatfox_iocs": [],
        "malwarebazaar_samples": [],
    }
    save_data("threats.json", data)


def seed_osint():
    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "greynoise": {"available": False, "note": "Set GREYNOISE_API_KEY for live data"},
        "otx_analysis": {
            "total_pulses": 48,
            "top_tags": [
                {"tag": "malware", "count": 32}, {"tag": "phishing", "count": 24},
                {"tag": "apt", "count": 18}, {"tag": "ransomware", "count": 16},
                {"tag": "china", "count": 14}, {"tag": "russia", "count": 12},
                {"tag": "rat", "count": 11}, {"tag": "c2", "count": 10},
                {"tag": "infostealer", "count": 9}, {"tag": "vulnerability", "count": 8},
            ],
            "targeted_countries": [
                {"country": "US", "count": 28}, {"country": "CN", "count": 15},
                {"country": "DE", "count": 12}, {"country": "GB", "count": 11},
                {"country": "AU", "count": 9}, {"country": "JP", "count": 8},
                {"country": "FR", "count": 7}, {"country": "IN", "count": 6},
                {"country": "KR", "count": 5}, {"country": "BR", "count": 4},
            ],
            "adversaries": [
                {"name": "APT40", "count": 4}, {"name": "Lazarus Group", "count": 3},
                {"name": "APT29", "count": 3}, {"name": "Mustang Panda", "count": 2},
                {"name": "Kimsuky", "count": 2},
            ],
            "malware_families": [
                {"family": "AgentTesla", "count": 8}, {"family": "Remcos", "count": 6},
                {"family": "Cobalt Strike", "count": 5}, {"family": "AsyncRAT", "count": 4},
                {"family": "PlugX", "count": 3}, {"family": "ShadowPad", "count": 2},
            ],
            "attack_techniques": [
                {"technique": "T1566 - Phishing", "count": 22},
                {"technique": "T1059 - Command and Scripting Interpreter", "count": 18},
                {"technique": "T1071 - Application Layer Protocol", "count": 15},
                {"technique": "T1105 - Ingress Tool Transfer", "count": 12},
                {"technique": "T1027 - Obfuscated Files or Information", "count": 11},
                {"technique": "T1547 - Boot or Logon Autostart Execution", "count": 9},
                {"technique": "T1082 - System Information Discovery", "count": 8},
                {"technique": "T1055 - Process Injection", "count": 7},
            ],
            "australia_relevant_count": 3,
            "australia_relevant": [
                {"name": "APT40 targeting Australian maritime sector", "adversary": "APT40", "tags": ["australia", "apt40", "maritime"], "indicator_count": 45},
                {"name": "Credential harvesting campaign targeting AU education", "adversary": "", "tags": ["australia", "phishing", "education"], "indicator_count": 23},
                {"name": "Critical infrastructure scanning activity - APAC", "adversary": "", "tags": ["apac", "scanning", "critical-infrastructure"], "indicator_count": 67},
            ],
        },
        "otx_pulses": [
            {"name": "APT40 targeting Australian maritime sector", "description": "Indicators associated with APT40 operations targeting Australian maritime and defence.", "created": "2026-03-07", "tags": ["australia", "apt40", "maritime"], "targeted_countries": ["AU"], "adversary": "APT40", "malware_families": ["ScanBox", "PlugX"], "attack_ids": ["T1566"], "indicator_count": 45},
            {"name": "Volt Typhoon living-off-the-land infrastructure", "description": "Network infrastructure associated with Volt Typhoon pre-positioning activities.", "created": "2026-03-05", "tags": ["china", "lotl", "critical-infrastructure"], "targeted_countries": ["US", "AU", "GB"], "adversary": "Volt Typhoon", "malware_families": [], "attack_ids": ["T1059", "T1071"], "indicator_count": 89},
            {"name": "LockBit 4.0 ransomware indicators", "description": "IOCs from recent LockBit 4.0 ransomware campaigns.", "created": "2026-03-04", "tags": ["ransomware", "lockbit"], "targeted_countries": ["US", "DE", "GB"], "adversary": "", "malware_families": ["LockBit"], "attack_ids": ["T1486"], "indicator_count": 112},
        ],
    }
    save_data("osint.json", data)


def seed_geopolitical():
    from .fetch_geopolitical import APAC_THREAT_ACTORS, AU_CYBER_POLICY

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "threat_actors": APAC_THREAT_ACTORS,
        "au_cyber_policy": AU_CYBER_POLICY,
        "news": [
            {"title": "ASPI: Australia's cyber deterrence posture needs strengthening", "link": "https://www.aspi.org.au/", "published": "2026-03-09T02:00:00Z", "summary": "Analysis of Australia's cyber deterrence capabilities in the context of rising APAC tensions.", "source": "ASPI"},
            {"title": "Salt Typhoon compromise of Australian telco confirmed", "link": "https://www.bleepingcomputer.com/", "published": "2026-03-08T10:00:00Z", "summary": "Australian telecommunications provider confirms breach linked to Salt Typhoon campaign.", "source": "BleepingComputer"},
            {"title": "ASPI: AUKUS Pillar II cyber cooperation accelerating", "link": "https://www.aspi.org.au/", "published": "2026-03-06T03:00:00Z", "summary": "Progress update on trilateral cyber capability development under AUKUS framework.", "source": "ASPI"},
            {"title": "Critical infrastructure ransomware attacks surge across APAC", "link": "https://www.bleepingcomputer.com/", "published": "2026-03-05T11:00:00Z", "summary": "Ransomware attacks targeting critical infrastructure in the Asia-Pacific region increased 40% in Q1 2026.", "source": "BleepingComputer"},
            {"title": "ASPI: China's offensive cyber capabilities assessment 2026", "link": "https://www.aspi.org.au/", "published": "2026-03-03T01:00:00Z", "summary": "Comprehensive assessment of PRC cyber operations capabilities and strategic intent.", "source": "ASPI"},
            {"title": "North Korean crypto theft funds ballistic missile programme", "link": "https://www.bleepingcomputer.com/", "published": "2026-03-02T09:00:00Z", "summary": "Analysis of how Lazarus Group cryptocurrency operations fund DPRK weapons programmes.", "source": "BleepingComputer"},
        ],
        "news_by_source": {"ASPI": 3, "BleepingComputer": 3},
    }
    save_data("geopolitical.json", data)


def seed_ndb():
    from .fetch_ndb import NDB_HISTORICAL
    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "OAIC Notifiable Data Breaches Reports",
        "source_url": "https://www.oaic.gov.au/privacy/notifiable-data-breaches/notifiable-data-breaches-publications",
        "trend_summary": [
            {"period": p["period"], "total": p["total_notifications"], "malicious": p["malicious_attacks"], "human_error": p["human_error"], "system_faults": p["system_faults"]}
            for p in NDB_HISTORICAL["reporting_periods"]
        ],
        "detailed_periods": NDB_HISTORICAL["reporting_periods"],
        "notable_breaches": NDB_HISTORICAL["notable_breaches"],
    }
    save_data("ndb.json", data)


def run():
    print("Seeding sample data...")
    seed_advisories()
    seed_vulnerabilities()
    seed_threats()
    seed_osint()
    seed_geopolitical()
    seed_ndb()
    print("Seed data complete!")


if __name__ == "__main__":
    run()
