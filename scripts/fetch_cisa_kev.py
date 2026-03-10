"""
Fetch CISA Known Exploited Vulnerabilities (KEV) catalog
and recent CVEs from the NVD API.
"""
from datetime import datetime, timedelta, timezone
from collections import Counter

from .config import SOURCES, NVD_API_KEY
from .utils import logger, save_data, fetch_url


def fetch_kev_catalog() -> dict:
    """Fetch the full CISA KEV catalog."""
    logger.info("Fetching CISA KEV catalog...")
    resp = fetch_url(SOURCES["cisa_kev"])
    if not resp:
        return {"vulnerabilities": [], "catalogVersion": "unknown"}

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    logger.info(f"  KEV catalog: {len(vulns)} known exploited vulnerabilities")
    return data


def fetch_recent_cves(days: int = 14, max_results: int = 100) -> list[dict]:
    """Fetch recent CVEs from NVD API (last N days)."""
    logger.info(f"Fetching recent CVEs (last {days} days)...")

    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": max_results,
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    resp = fetch_url(SOURCES["nvd_cve_api"], headers=headers, params=params)
    if not resp:
        return []

    data = resp.json()
    cves = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract CVSS score
        cvss_score = None
        cvss_severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        # Extract description
        descriptions = cve.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            ""
        )

        cves.append({
            "id": cve_id,
            "published": cve.get("published", ""),
            "lastModified": cve.get("lastModified", ""),
            "description": desc_en[:300],
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "source": "NVD",
        })

    logger.info(f"  NVD: {len(cves)} recent CVEs")
    return cves


def analyse_kev(kev_data: dict) -> dict:
    """Produce summary statistics from KEV data."""
    vulns = kev_data.get("vulnerabilities", [])

    # Recent additions (last 30 days)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    recent = [v for v in vulns if v.get("dateAdded", "") >= cutoff]

    # Top vendors
    vendor_counts = Counter(v.get("vendorProject", "Unknown") for v in vulns)
    top_vendors = vendor_counts.most_common(15)

    # Overdue remediations
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    overdue = [v for v in vulns if v.get("dueDate", "9999") < today]

    return {
        "total_kev": len(vulns),
        "recent_30d": len(recent),
        "recent_entries": recent[:20],
        "top_vendors": [{"vendor": v, "count": c} for v, c in top_vendors],
        "overdue_count": len(overdue),
    }


def run():
    """Fetch all vulnerability data and save."""
    kev_data = fetch_kev_catalog()
    kev_analysis = analyse_kev(kev_data)
    recent_cves = fetch_recent_cves()

    # Severity distribution for recent CVEs
    severity_dist = Counter(c["cvss_severity"] for c in recent_cves)
    critical_cves = [c for c in recent_cves if c.get("cvss_score") and c["cvss_score"] >= 9.0]

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "kev": kev_analysis,
        "recent_cves": {
            "total": len(recent_cves),
            "severity_distribution": dict(severity_dist),
            "critical": critical_cves[:20],
            "all": recent_cves,
        },
    }

    save_data("vulnerabilities.json", data)
    return data


if __name__ == "__main__":
    run()
