# :material-bug: Vulnerabilities & Known Exploited Vulnerabilities

**Last updated:** 2026-03-10 14:39 UTC

## CISA Known Exploited Vulnerabilities (KEV)

The KEV catalog tracks vulnerabilities confirmed to be actively exploited in the wild.

| Metric | Value |
|--------|-------|
| Total KEV entries | **1247** |
| Added in last 30 days | **18** |
| Overdue remediations | **42** |

### Top Affected Vendors (KEV)

<canvas id="kevVendorChart" width="800" height="400"></canvas>

| Vendor | Exploited CVEs |
|--------|---------------|
| Microsoft | 312 |
| Apple | 89 |
| Google | 78 |
| Cisco | 67 |
| Adobe | 65 |
| Fortinet | 42 |
| Ivanti | 38 |
| VMware | 35 |
| Oracle | 31 |
| Palo Alto Networks | 28 |
| Apache | 26 |
| Citrix | 24 |
| SonicWall | 19 |
| Samsung | 17 |
| D-Link | 15 |

### Recently Added to KEV (Last 30 Days)

| CVE | Vendor | Product | Date Added | Due Date |
|-----|--------|---------|------------|----------|
| CVE-2026-1234 | Fortinet | FortiOS | 2026-03-08 | 2026-03-29 |
| CVE-2026-0987 | SonicWall | SMA 100 | 2026-03-06 | 2026-03-27 |
| CVE-2025-9876 | Ivanti | Connect Secure | 2026-03-04 | 2026-03-25 |
| CVE-2026-0555 | Apache | Tomcat | 2026-03-02 | 2026-03-23 |
| CVE-2025-8765 | Cisco | IOS XE | 2026-02-28 | 2026-03-21 |

---

## Recent CVEs (Last 14 Days)

**Total new CVEs:** 847

### Severity Distribution

<canvas id="cveSeverityChart" width="400" height="300"></canvas>

| Severity | Count |
|----------|-------|
| CRITICAL | 43 |
| HIGH | 218 |
| MEDIUM | 389 |
| LOW | 112 |
| UNKNOWN | 85 |

### Critical CVEs (CVSS >= 9.0)

| CVE ID | CVSS | Description |
|--------|------|-------------|
| **CVE-2026-1234** | 9.8 | Heap-based buffer overflow in Fortinet FortiOS SSL-VPN allows remote code execution via crafted HTTP requests. |
| **CVE-2026-0987** | 9.8 | Authentication bypass in SonicWall SMA 100 series allows unauthenticated attackers to gain admin access. |
| **CVE-2026-0555** | 9.1 | Remote code execution in Apache Tomcat via deserialization of untrusted data in session persistence. |
| **CVE-2026-0888** | 9.8 | SQL injection in WordPress plugin allowing unauthenticated database access. |
| **CVE-2025-9876** | 9.0 | Server-side request forgery in Ivanti Connect Secure allows authenticated admin to access internal services. |
