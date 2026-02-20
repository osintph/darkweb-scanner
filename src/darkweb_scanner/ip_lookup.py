"""
IP Investigation module — AbuseIPDB + VirusTotal enrichment.
Pulls every available field from both APIs for a given IP address.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


async def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Full AbuseIPDB check with verbose reports."""
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}

    async with aiohttp.ClientSession() as client:
        async with client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 401:
                return {"error": "Invalid AbuseIPDB API key"}
            if resp.status == 429:
                return {"error": "AbuseIPDB rate limit — retry later"}
            if resp.status != 200:
                return {"error": f"AbuseIPDB HTTP {resp.status}"}
            raw = await resp.json()
            d = raw.get("data", {})

            # Enrich reports with category names
            reports = []
            for r in (d.get("reports") or [])[:20]:
                cats = [ABUSE_CATEGORIES.get(c, f"Cat {c}") for c in (r.get("categories") or [])]
                reports.append({
                    "reported_at": r.get("reportedAt"),
                    "comment": r.get("comment", "")[:300],
                    "categories": cats,
                    "reporter_country": r.get("reporterCountryName"),
                })

            return {
                "ip": d.get("ipAddress"),
                "is_public": d.get("isPublic"),
                "ip_version": d.get("ipVersion"),
                "is_whitelisted": d.get("isWhitelisted"),
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "country_code": d.get("countryCode"),
                "country_name": d.get("countryName"),
                "usage_type": d.get("usageType"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "hostnames": d.get("hostnames") or [],
                "is_tor": d.get("isTor", False),
                "total_reports": d.get("totalReports", 0),
                "num_distinct_users": d.get("numDistinctUsers", 0),
                "last_reported_at": d.get("lastReportedAt"),
                "reports": reports,
            }


async def check_virustotal(ip: str, api_key: str) -> dict:
    """Full VirusTotal IP check — main report + resolutions + communicating files."""
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    base = "https://www.virustotal.com/api/v3"

    async with aiohttp.ClientSession() as client:

        # ── Main IP report ──
        async with client.get(
            f"{base}/ip_addresses/{ip}",
            headers=headers, timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 401:
                return {"error": "Invalid VirusTotal API key"}
            if resp.status == 404:
                return {"error": "IP not found in VirusTotal"}
            if resp.status == 429:
                return {"error": "VirusTotal rate limit — 4 req/min on free tier"}
            if resp.status != 200:
                return {"error": f"VirusTotal HTTP {resp.status}"}
            main = await resp.json()

        attrs = main.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        # Parse all engine results
        engine_results = attrs.get("last_analysis_results", {})
        malicious_engines = [
            {"engine": name, "result": info.get("result"), "category": info.get("category")}
            for name, info in engine_results.items()
            if info.get("category") in ("malicious", "suspicious")
        ]

        # Parse SSL cert
        ssl_cert = attrs.get("last_https_certificate", {})
        ssl_info = None
        if ssl_cert:
            subject = ssl_cert.get("subject", {})
            issuer = ssl_cert.get("issuer", {})
            validity = ssl_cert.get("validity", {})
            ssl_info = {
                "subject_cn": subject.get("CN"),
                "subject_org": subject.get("O"),
                "issuer_cn": issuer.get("CN"),
                "issuer_org": issuer.get("O"),
                "valid_from": validity.get("not_before"),
                "valid_to": validity.get("not_after"),
                "serial": ssl_cert.get("serial_number"),
                "thumbprint": ssl_cert.get("thumbprint"),
            }

        # Parse WHOIS
        whois_raw = attrs.get("whois", "")
        whois_date = attrs.get("whois_date")
        if whois_date:
            try:
                whois_date = datetime.fromtimestamp(whois_date, tz=timezone.utc).isoformat()
            except Exception:
                pass

        # Last analysis date
        last_analysis = attrs.get("last_analysis_date")
        if last_analysis:
            try:
                last_analysis = datetime.fromtimestamp(last_analysis, tz=timezone.utc).isoformat()
            except Exception:
                pass

        result = {
            "ip": ip,
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "continent": attrs.get("continent"),
            "country": attrs.get("country"),
            "network": attrs.get("network"),
            "regional_internet_registry": attrs.get("regional_internet_registry"),
            "reputation": attrs.get("reputation", 0),
            "jarm": attrs.get("jarm"),
            "tags": attrs.get("tags") or [],
            "total_votes": attrs.get("total_votes", {}),
            "last_analysis_date": last_analysis,
            "last_modification_date": attrs.get("last_modification_date"),
            "analysis_stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
            },
            "malicious_engines": malicious_engines,
            "total_engines": len(engine_results),
            "ssl_certificate": ssl_info,
            "whois": whois_raw[:3000] if whois_raw else None,
            "whois_date": whois_date,
            "resolutions": [],
            "communicating_files": [],
        }

        # ── Resolutions (historical DNS) ── rate limit: wait before next call
        await asyncio.sleep(16)  # VT free = 4 req/min
        async with client.get(
            f"{base}/ip_addresses/{ip}/resolutions",
            headers=headers, params={"limit": "20"},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                res_data = await resp.json()
                for item in (res_data.get("data") or []):
                    ra = item.get("attributes", {})
                    result["resolutions"].append({
                        "hostname": ra.get("host_name"),
                        "date": ra.get("date"),
                        "resolver": ra.get("resolver"),
                    })

        # ── Communicating files (malware) ──
        await asyncio.sleep(16)
        async with client.get(
            f"{base}/ip_addresses/{ip}/communicating_files",
            headers=headers, params={"limit": "10"},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                cf_data = await resp.json()
                for item in (cf_data.get("data") or []):
                    fa = item.get("attributes", {})
                    fa_stats = fa.get("last_analysis_stats", {})
                    result["communicating_files"].append({
                        "sha256": item.get("id"),
                        "name": (fa.get("meaningful_name") or fa.get("name", "unknown")),
                        "type": fa.get("type_description"),
                        "size": fa.get("size"),
                        "malicious": fa_stats.get("malicious", 0),
                        "suspicious": fa_stats.get("suspicious", 0),
                        "first_seen": fa.get("first_submission_date"),
                        "last_seen": fa.get("last_analysis_date"),
                    })

        return result


async def investigate_ip(ip: str, abuseipdb_key: str = "", virustotal_key: str = "") -> dict:
    """Run full IP investigation against both APIs concurrently where possible."""
    abuse_key = abuseipdb_key or ABUSEIPDB_KEY
    vt_key = virustotal_key or VIRUSTOTAL_KEY

    results = {"ip": ip, "abuseipdb": None, "virustotal": None}

    # Run AbuseIPDB first (fast), then VT (slow due to rate limits)
    if abuse_key:
        try:
            results["abuseipdb"] = await check_abuseipdb(ip, abuse_key)
        except Exception as e:
            results["abuseipdb"] = {"error": str(e)}
    else:
        results["abuseipdb"] = {"error": "ABUSEIPDB_API_KEY not configured"}

    if vt_key:
        try:
            results["virustotal"] = await check_virustotal(ip, vt_key)
        except Exception as e:
            results["virustotal"] = {"error": str(e)}
    else:
        results["virustotal"] = {"error": "VIRUSTOTAL_API_KEY not configured"}

    return results
