"""
DNS Crawler — passive + active DNS reconnaissance.
Sources: dnspython (active), crt.sh (passive CT logs),
         HackerTarget (passive), ip-api.com (geolocation).
No paid API keys required.
"""

import logging
import socket
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10
DNS_TIMEOUT = 5


# ── Helpers ────────────────────────────────────────────────────────────────────

def _clean_domain(domain: str) -> str:
    """Strip protocol, path, trailing dots."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"/.*$", "", domain)
    domain = domain.rstrip(".")
    return domain


def _safe_http(url: str, method: str = "get", **kwargs) -> Optional[requests.Response]:
    try:
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        kwargs.setdefault("headers", {"User-Agent": "OSINTPH-DNSCrawler/1.0"})
        return getattr(requests, method)(url, **kwargs)
    except Exception as e:
        logger.debug(f"HTTP {method} {url} failed: {e}")
        return None


# ── Active DNS resolution ──────────────────────────────────────────────────────

def query_dns_records(domain: str) -> dict:
    """
    Query all common DNS record types directly.
    Returns dict of record_type -> list of values.
    """
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        logger.error("dnspython not installed")
        return {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    results = {}

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            values = []
            for rdata in answers:
                val = rdata.to_text()
                # Clean up trailing dots
                if val.endswith("."):
                    val = val[:-1]
                values.append(val)
            if values:
                results[rtype] = values
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.exception.DNSException):
            pass
        except Exception as e:
            logger.debug(f"DNS {rtype} query for {domain} failed: {e}")

    return results


def attempt_zone_transfer(domain: str) -> dict:
    """
    Attempt AXFR zone transfer against all NS servers.
    Returns results per nameserver.
    """
    try:
        import dns.resolver
        import dns.zone
        import dns.query
        import dns.exception
    except ImportError:
        return {"error": "dnspython not installed"}

    results = {}
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=DNS_TIMEOUT)
        nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answers]
    except Exception as e:
        return {"error": f"Could not resolve NS records: {e}"}

    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=DNS_TIMEOUT))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "value": rdata.to_text().rstrip("."),
                        })
            results[ns] = {
                "success": True,
                "record_count": len(records),
                "records": records[:200],  # cap output
            }
            logger.warning(f"ZONE TRANSFER SUCCEEDED on {ns} for {domain}")
        except Exception as e:
            results[ns] = {"success": False, "error": str(e)}

    return results


def reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup for an IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_ip(hostname: str) -> list[str]:
    """Resolve hostname to IPs."""
    try:
        info = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in info})
    except Exception:
        return []


# ── Passive: certificate transparency (crt.sh) ────────────────────────────────

def fetch_crtsh(domain: str) -> list[dict]:
    """
    Query crt.sh for all certificates issued for domain.
    Returns list of subdomains with cert metadata.
    """
    resp = _safe_http(
        f"https://crt.sh/?q=%.{domain}&output=json",
        headers={"User-Agent": "OSINTPH-DNSCrawler/1.0"},
    )
    if not resp or resp.status_code != 200:
        return []

    try:
        data = resp.json()
    except Exception:
        return []

    seen = set()
    results = []
    for entry in data:
        # name_value can contain \n-separated SANs
        names = entry.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lower().lstrip("*.")
            if not name or name in seen:
                continue
            if not name.endswith(domain):
                continue
            seen.add(name)
            results.append({
                "subdomain": name,
                "issuer": entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "cert_id": entry.get("id"),
            })

    # Sort: base domain first, then alphabetically
    results.sort(key=lambda x: (x["subdomain"] != domain, x["subdomain"]))
    return results


# ── Passive: HackerTarget DNS lookup ──────────────────────────────────────────

def fetch_hackertarget(domain: str) -> list[str]:
    """
    HackerTarget free API for subdomain enumeration.
    Returns list of subdomains (free tier: 20 results).
    """
    resp = _safe_http(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not resp or resp.status_code != 200:
        return []

    subdomains = []
    for line in resp.text.splitlines():
        parts = line.strip().split(",")
        if parts and parts[0].endswith(domain):
            subdomains.append(parts[0].strip())
    return subdomains


# ── Passive: DNS history via HackerTarget ─────────────────────────────────────

def fetch_dns_history(domain: str) -> list[dict]:
    """Fetch DNS history from HackerTarget."""
    resp = _safe_http(f"https://api.hackertarget.com/dnslookup/?q={domain}")
    if not resp or resp.status_code != 200:
        return []
    records = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith("error"):
            records.append({"raw": line})
    return records


# ── Passive: ASN / IP geolocation ─────────────────────────────────────────────

def geolocate_ips(ips: list[str]) -> dict[str, dict]:
    """
    Bulk geolocate IPs using ip-api.com (free, 100/min limit).
    Returns dict of ip -> geo data.
    """
    if not ips:
        return {}

    # Batch up to 100
    batch = ips[:100]
    resp = _safe_http(
        "http://ip-api.com/batch",
        method="post",
        json=[{"query": ip, "fields": "status,country,countryCode,regionName,city,org,as,isp,query"} for ip in batch],
    )
    if not resp or resp.status_code != 200:
        # Fall back to individual lookups
        results = {}
        for ip in batch[:10]:  # limit fallback
            r = _safe_http(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,org,as,isp,query")
            if r and r.status_code == 200:
                try:
                    results[ip] = r.json()
                except Exception:
                    pass
        return results

    try:
        data = resp.json()
        return {entry.get("query", ""): entry for entry in data if entry.get("status") == "success"}
    except Exception:
        return {}


# ── SPF / DMARC / DKIM analysis ───────────────────────────────────────────────

def analyze_email_security(domain: str, dns_records: dict) -> dict:
    """Analyse SPF, DMARC, DKIM from already-fetched DNS records."""
    analysis = {
        "spf": None,
        "spf_valid": False,
        "dmarc": None,
        "dmarc_valid": False,
        "dkim_selectors_found": [],
        "issues": [],
    }

    # SPF
    for txt in dns_records.get("TXT", []):
        if txt.startswith('"v=spf1') or txt.startswith("v=spf1"):
            analysis["spf"] = txt.strip('"')
            analysis["spf_valid"] = True
            break
    if not analysis["spf_valid"]:
        analysis["issues"].append("No SPF record — domain vulnerable to email spoofing")

    # DMARC
    try:
        import dns.resolver
        import dns.exception
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DNS_TIMEOUT)
        for rdata in answers:
            val = rdata.to_text().strip('"')
            if "v=DMARC1" in val:
                analysis["dmarc"] = val
                analysis["dmarc_valid"] = True
                if "p=none" in val:
                    analysis["issues"].append("DMARC policy is 'none' — monitoring only, no enforcement")
                break
    except Exception:
        pass
    if not analysis["dmarc_valid"]:
        analysis["issues"].append("No DMARC record — email authentication not enforced")

    # DKIM — check common selectors
    common_selectors = ["default", "google", "k1", "k2", "mail", "dkim", "selector1", "selector2", "smtp", "email"]
    try:
        import dns.resolver
        import dns.exception
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        for sel in common_selectors:
            try:
                resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=2)
                analysis["dkim_selectors_found"].append(sel)
            except Exception:
                pass
    except Exception:
        pass

    return analysis


# ── Subdomain resolution with geolocation ─────────────────────────────────────

def resolve_subdomains(subdomains: list[str], max_workers: int = 20) -> list[dict]:
    """
    Resolve a list of subdomains to IPs in parallel, then geolocate.
    """
    resolved = []

    def resolve_one(sub: str) -> Optional[dict]:
        ips = resolve_ip(sub)
        if ips:
            return {"subdomain": sub, "ips": ips}
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(resolve_one, s): s for s in subdomains[:300]}
        for future in as_completed(futures):
            result = future.result()
            if result:
                resolved.append(result)

    # Geolocate all unique IPs
    all_ips = list({ip for r in resolved for ip in r["ips"]})
    geo = geolocate_ips(all_ips)
    for r in resolved:
        r["geo"] = [geo.get(ip, {}) for ip in r["ips"]]

    resolved.sort(key=lambda x: x["subdomain"])
    return resolved


# ── Master recon function ──────────────────────────────────────────────────────

def run_dns_recon(domain: str) -> dict:
    """
    Full DNS reconnaissance on a domain.
    Runs passive (crt.sh, HackerTarget) and active (dnspython) in parallel.
    Returns structured result dict suitable for storage and display.
    """
    domain = _clean_domain(domain)
    started_at = datetime.utcnow().isoformat()
    logger.info(f"Starting DNS recon for {domain}")

    result = {
        "domain": domain,
        "started_at": started_at,
        "dns_records": {},
        "zone_transfer": {},
        "subdomains_passive": [],
        "subdomains_resolved": [],
        "email_security": {},
        "errors": [],
    }

    # ── Phase 1: parallel passive + active fetch ──
    with ThreadPoolExecutor(max_workers=6) as ex:
        f_dns = ex.submit(query_dns_records, domain)
        f_crtsh = ex.submit(fetch_crtsh, domain)
        f_ht = ex.submit(fetch_hackertarget, domain)
        f_axfr = ex.submit(attempt_zone_transfer, domain)

        try:
            result["dns_records"] = f_dns.result(timeout=15)
        except Exception as e:
            result["errors"].append(f"DNS records: {e}")

        try:
            crt_entries = f_crtsh.result(timeout=20)
            result["subdomains_passive"] = crt_entries
        except Exception as e:
            result["errors"].append(f"crt.sh: {e}")

        try:
            ht_subs = f_ht.result(timeout=15)
        except Exception as e:
            ht_subs = []
            result["errors"].append(f"HackerTarget: {e}")

        try:
            result["zone_transfer"] = f_axfr.result(timeout=20)
        except Exception as e:
            result["errors"].append(f"Zone transfer: {e}")

    # ── Phase 2: merge + deduplicate subdomains ──
    crt_subs = {e["subdomain"] for e in result["subdomains_passive"]}
    all_subs = crt_subs | set(ht_subs)
    # Add NS/MX hostnames
    for ns in result["dns_records"].get("NS", []):
        if ns.endswith(f".{domain}") or ns == domain:
            all_subs.add(ns)
    for mx in result["dns_records"].get("MX", []):
        # MX format: "10 mail.example.com"
        parts = mx.split()
        host = parts[-1] if parts else mx
        if host.endswith(f".{domain}"):
            all_subs.add(host)

    # ── Phase 3: resolve all subdomains ──
    result["subdomains_resolved"] = resolve_subdomains(list(all_subs))

    # ── Phase 4: email security analysis ──
    result["email_security"] = analyze_email_security(domain, result["dns_records"])

    # ── Phase 5: reverse DNS on main A records ──
    main_ips = result["dns_records"].get("A", [])
    ptr_records = {}
    for ip in main_ips[:10]:
        ptr = reverse_dns(ip)
        if ptr:
            ptr_records[ip] = ptr
    result["ptr_records"] = ptr_records

    # ── Phase 6: geolocate main IPs ──
    result["ip_geo"] = geolocate_ips(main_ips[:20])

    result["completed_at"] = datetime.utcnow().isoformat()
    result["subdomain_count"] = len(all_subs)
    result["resolved_count"] = len(result["subdomains_resolved"])

    logger.info(
        f"DNS recon complete for {domain}: "
        f"{result['subdomain_count']} subdomains, "
        f"{result['resolved_count']} resolved"
    )
    return result
