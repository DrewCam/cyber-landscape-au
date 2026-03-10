"""
Australian Notifiable Data Breaches (NDB) statistics.
OAIC publishes quarterly/bi-annual reports. Since there is no live API,
this module maintains curated reference data from published OAIC reports
and can be updated when new reports are released.
"""
from datetime import datetime, timezone

from .utils import logger, save_data


# Curated NDB data from OAIC published reports
# Source: https://www.oaic.gov.au/privacy/notifiable-data-breaches/notifiable-data-breaches-publications
NDB_HISTORICAL = {
    "reporting_periods": [
        {
            "period": "Jul-Dec 2023",
            "total_notifications": 483,
            "malicious_attacks": 310,
            "human_error": 144,
            "system_faults": 29,
            "top_sectors": [
                {"sector": "Health service providers", "count": 104},
                {"sector": "Finance", "count": 49},
                {"sector": "Australian Government", "count": 42},
                {"sector": "Insurance", "count": 35},
                {"sector": "Education", "count": 33},
            ],
            "breach_types": {
                "cyber_incident": 203,
                "ransomware": 42,
                "phishing": 56,
                "compromised_credentials": 52,
                "social_engineering": 18,
                "other_malicious": 29,
                "human_error_disclosure": 95,
                "human_error_loss": 12,
                "system_fault": 29,
            },
            "data_types_affected": [
                "Contact information",
                "Identity information",
                "Financial details",
                "Health information",
                "Tax file numbers",
            ],
            "individuals_affected": {
                "1-100": 249,
                "101-1000": 97,
                "1001-10000": 51,
                "10001-100000": 27,
                "100000+": 12,
            },
        },
        {
            "period": "Jan-Jun 2023",
            "total_notifications": 409,
            "malicious_attacks": 264,
            "human_error": 123,
            "system_faults": 22,
            "top_sectors": [
                {"sector": "Health service providers", "count": 93},
                {"sector": "Finance", "count": 54},
                {"sector": "Australian Government", "count": 37},
                {"sector": "Education", "count": 31},
                {"sector": "Legal, accounting, management", "count": 25},
            ],
        },
        {
            "period": "Jul-Dec 2022",
            "total_notifications": 497,
            "malicious_attacks": 350,
            "human_error": 123,
            "system_faults": 24,
            "top_sectors": [
                {"sector": "Health service providers", "count": 71},
                {"sector": "Finance", "count": 68},
                {"sector": "Australian Government", "count": 40},
                {"sector": "Insurance", "count": 37},
                {"sector": "Education", "count": 29},
            ],
        },
        {
            "period": "Jan-Jun 2022",
            "total_notifications": 396,
            "malicious_attacks": 250,
            "human_error": 123,
            "system_faults": 23,
            "top_sectors": [
                {"sector": "Health service providers", "count": 79},
                {"sector": "Finance", "count": 45},
                {"sector": "Education", "count": 32},
                {"sector": "Australian Government", "count": 30},
                {"sector": "Retail", "count": 20},
            ],
        },
        {
            "period": "Jul-Dec 2021",
            "total_notifications": 464,
            "malicious_attacks": 277,
            "human_error": 153,
            "system_faults": 34,
            "top_sectors": [
                {"sector": "Health service providers", "count": 83},
                {"sector": "Finance", "count": 56},
                {"sector": "Australian Government", "count": 38},
                {"sector": "Insurance", "count": 29},
                {"sector": "Legal, accounting, management", "count": 26},
            ],
        },
        {
            "period": "Jan-Jun 2021",
            "total_notifications": 446,
            "malicious_attacks": 289,
            "human_error": 134,
            "system_faults": 23,
            "top_sectors": [
                {"sector": "Health service providers", "count": 81},
                {"sector": "Finance", "count": 58},
                {"sector": "Australian Government", "count": 41},
                {"sector": "Legal, accounting, management", "count": 27},
                {"sector": "Education", "count": 25},
            ],
        },
    ],
    # Major Australian data breaches (notable incidents)
    "notable_breaches": [
        {
            "entity": "Optus",
            "date": "September 2022",
            "records_affected": "9,800,000",
            "data_types": "Names, dates of birth, phone numbers, email addresses, passport/driver licence numbers",
            "attack_type": "API vulnerability exploitation",
        },
        {
            "entity": "Medibank",
            "date": "October 2022",
            "records_affected": "9,700,000",
            "data_types": "Personal details, health claims data, Medicare numbers",
            "attack_type": "Compromised credentials, ransomware (REvil affiliate)",
        },
        {
            "entity": "Latitude Financial",
            "date": "March 2023",
            "records_affected": "14,000,000",
            "data_types": "Driver licences, passports, financial statements",
            "attack_type": "Compromised employee credentials",
        },
        {
            "entity": "HWL Ebsworth",
            "date": "April 2023",
            "records_affected": "2,700,000",
            "data_types": "Legal documents, client data, government information",
            "attack_type": "ALPHV/BlackCat ransomware",
        },
        {
            "entity": "DP World Australia",
            "date": "November 2023",
            "records_affected": "Unknown",
            "data_types": "Employee records, port operations data",
            "attack_type": "Network intrusion (disrupted port operations for 3 days)",
        },
        {
            "entity": "Court Services Victoria",
            "date": "January 2024",
            "records_affected": "Unknown",
            "data_types": "Court recordings, hearing records",
            "attack_type": "Ransomware (Qilin)",
        },
        {
            "entity": "MediSecure",
            "date": "May 2024",
            "records_affected": "12,900,000",
            "data_types": "Personal and health information, prescription data",
            "attack_type": "Ransomware",
        },
    ],
}


def run():
    """Save NDB reference data."""
    logger.info("Saving OAIC NDB reference data...")

    # Compute trend summary
    periods = NDB_HISTORICAL["reporting_periods"]
    trend = []
    for p in periods:
        trend.append({
            "period": p["period"],
            "total": p["total_notifications"],
            "malicious": p["malicious_attacks"],
            "human_error": p["human_error"],
            "system_faults": p["system_faults"],
        })

    data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "OAIC Notifiable Data Breaches Reports",
        "source_url": "https://www.oaic.gov.au/privacy/notifiable-data-breaches/notifiable-data-breaches-publications",
        "trend_summary": trend,
        "detailed_periods": NDB_HISTORICAL["reporting_periods"],
        "notable_breaches": NDB_HISTORICAL["notable_breaches"],
    }

    save_data("ndb.json", data)
    return data


if __name__ == "__main__":
    run()
