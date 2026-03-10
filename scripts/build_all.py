#!/usr/bin/env python3
"""
Master build script: fetches all data sources, then generates markdown pages.
Run this before `mkdocs build` to produce fresh content.

Usage:
    python -m scripts.build_all          # Fetch everything + generate pages
    python -m scripts.build_all --skip-fetch  # Only regenerate pages from cached data
"""
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
    else:
        logger.info("Skipping data fetch (using cached data)")

    generate_all()

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info(f"\nBuild completed in {elapsed:.1f} seconds")


if __name__ == "__main__":
    main()
