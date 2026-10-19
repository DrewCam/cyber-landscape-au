#!/usr/bin/env python3
"""
Master build script: fetches all data sources, then generates markdown pages.
Run this before `mkdocs build` to produce fresh content.

Usage:
    python -m scripts.build_all          # Fetch everything + generate pages
    python -m scripts.build_all --skip-fetch  # Only regenerate pages from cached data
"""
import os
import sys
import argparse
import traceback
from datetime import datetime, timezone

from .utils import logger


def fetch_all():
    """Run all data fetcher modules."""
    fetchers = [
        ("ACSC/Five Eyes CERTs/CISA Advisories", "scripts.fetch_acsc"),
        ("CISA KEV & NVD CVEs", "scripts.fetch_cisa_kev"),
        ("abuse.ch Threat Feeds", "scripts.fetch_abuse_ch"),
        ("OSINT (OTX, GreyNoise)", "scripts.fetch_osint"),
        ("Geopolitical Intelligence", "scripts.fetch_geopolitical"),
        ("OAIC NDB Statistics", "scripts.fetch_ndb"),
        ("Shodan Internet Exposure", "scripts.fetch_shodan"),
    ]

    results = {}
    for name, module_path in fetchers:
        logger.info(f"{'=' * 60}")
        logger.info(f"Fetching: {name}")
        logger.info(f"{'=' * 60}")
        try:
            import importlib
            mod = importlib.import_module(module_path)
            data = mod.run()
            results[name] = {"status": "success", "data": data}
            logger.info(f"  OK: {name}")
        except Exception as e:
            logger.error(f"  FAILED: {name}: {e}")
            traceback.print_exc()
            results[name] = {"status": "error", "error": str(e)}

    return results


def write_step_summary(results: dict):
    """Write a per-source health table to the GitHub Actions job summary.

    Fetchers log and continue on errors so one bad source doesn't block the
    deploy; this makes those partial failures visible on the run page.
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    def count(data, *path):
        for key in path:
            if not isinstance(data, dict):
                return 0
            data = data.get(key)
        return len(data) if isinstance(data, (list, dict)) else (data or 0)

    rows = []
    for name, r in results.items():
        if r["status"] == "error":
            rows.append(f"| {name} | :x: error | {r['error']} |")
    data = {name: r.get("data") or {} for name, r in results.items()}
    checks = [
        ("ASD/ACSC feeds", "ACSC/Five Eyes CERTs/CISA Advisories",
         lambda d: sum(v for k, v in d.get("by_source", {}).items() if k.startswith("ACSC"))),
        ("Advisories (all sources)", "ACSC/Five Eyes CERTs/CISA Advisories", lambda d: d.get("total_count", 0)),
        ("CISA KEV", "CISA KEV & NVD CVEs", lambda d: count(d, "kev", "total_kev")),
        ("NVD recent CVEs", "CISA KEV & NVD CVEs", lambda d: count(d, "recent_cves", "total")),
        ("URLhaus", "abuse.ch Threat Feeds", lambda d: count(d, "urlhaus_urls")),
        ("ThreatFox", "abuse.ch Threat Feeds", lambda d: count(d, "threatfox_iocs")),
        ("MalwareBazaar", "abuse.ch Threat Feeds", lambda d: count(d, "malwarebazaar_samples")),
        ("OTX pulses", "OSINT (OTX, GreyNoise)", lambda d: count(d, "otx_pulses")),
        ("MITRE ATT&CK groups", "Geopolitical Intelligence", lambda d: count(d, "threat_actors")),
        ("News (ASPI + BleepingComputer)", "Geopolitical Intelligence", lambda d: count(d, "news")),
        ("OAIC NDB notifications", "OAIC NDB Statistics", lambda d: d.get("total", 0)),
        ("Shodan exposure queries", "Shodan Internet Exposure",
         lambda d: count(d, "shodan", "exposure_results")),
    ]
    for label, fetcher, fn in checks:
        if results.get(fetcher, {}).get("status") != "success":
            continue
        n = fn(data[fetcher])
        status = ":white_check_mark:" if n else ":warning: empty"
        rows.append(f"| {label} | {status} | {n} items |")

    with open(summary_path, "a", encoding="utf-8") as f:
        f.write("## Data source health\n\n| Source | Status | Detail |\n|---|---|---|\n")
        f.write("\n".join(rows) + "\n")


def generate_all():
    """Run the page generator."""
    logger.info(f"{'=' * 60}")
    logger.info("Generating markdown pages...")
    logger.info(f"{'=' * 60}")
    from .generate_pages import generate_all_pages
    generate_all_pages()


def main():
    parser = argparse.ArgumentParser(description="Build Australian Cyber Threat Landscape")
    parser.add_argument("--skip-fetch", action="store_true",
                        help="Skip data fetching, only regenerate pages")
    args = parser.parse_args()

    start = datetime.now(timezone.utc)
    logger.info(f"Build started at {start.isoformat()}")

    if not args.skip_fetch:
        results = fetch_all()
        succeeded = sum(1 for r in results.values() if r["status"] == "success")
        failed = sum(1 for r in results.values() if r["status"] == "error")
        logger.info(f"\nFetch summary: {succeeded} succeeded, {failed} failed")
        write_step_summary(results)
    else:
        logger.info("Skipping data fetch (using cached data)")

    generate_all()

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info(f"\nBuild completed in {elapsed:.1f} seconds")


if __name__ == "__main__":
    main()
