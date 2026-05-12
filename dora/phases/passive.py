from __future__ import annotations

import asyncio
import ipaddress
import re
from urllib.parse import urljoin, urlparse

import dns.resolver
from bs4 import BeautifulSoup

from dora.config import DORAConfig
from dora.models import Finding, FindingType, Severity, Target
from dora.utils.http import AsyncHTTPClient


def _extract_domain_parts(domain: str) -> list[str]:
    parts = domain.split(".")
    if len(parts) >= 2:
        return [parts[-2], parts[-1]]
    return parts


def _domain_to_tld(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


async def run_crtsh(client: AsyncHTTPClient, domain: str) -> list[dict]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        data = await client.fetch_json(url)
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)
        return [{"subdomain": s, "source": "crt.sh"} for s in subdomains]
    except Exception:
        return []


async def run_wayback(client: AsyncHTTPClient, domain: str) -> list[dict]:
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original,timestamp,statuscode&limit=5000"
    try:
        data = await client.fetch_json(url)
        urls = set()
        subdomains = set()
        for entry in data[1:]:
            if len(entry) >= 1:
                original = entry[0]
                urls.add(original)
                parsed = urlparse(original)
                hostname = parsed.hostname or ""
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subdomains.add(hostname)
        return [{"subdomain": s, "source": "wayback", "urls_found": len(urls)} for s in subdomains]
    except Exception:
        return []


async def run_dns_enum(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=10)
            values = [str(r) for r in answers]
            findings.append(Finding(
                type=FindingType.DNS_RECORD,
                name=f"DNS {rtype} Record",
                severity=Severity.INFO,
                value=domain,
                description=f"Found {len(values)} {rtype} record(s)",
                evidence=", ".join(values[:5]),
                source=f"dns.{rtype}",
                extra={"record_type": rtype, "values": values},
            ))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.LifetimeTimeout:
            pass
        except Exception:
            pass

    return findings


async def check_zone_transfer(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=10)
        for ns in ns_answers:
            ns_str = str(ns).rstrip(".")
            try:
                import socket
                ns_ip = socket.gethostbyname(ns_str)
                zt = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                if zt and len(zt.nodes) > 0:
                    findings.append(Finding(
                        type=FindingType.DNS_RECORD,
                        name="Zone Transfer Vulnerable",
                        severity=Severity.HIGH,
                        value=domain,
                        description=f"DNS zone transfer allowed on {ns_str} ({ns_ip})",
                        evidence=f"Records: {len(zt.nodes)}",
                        source="dns.zone_transfer",
                    ))
            except Exception:
                pass
    except Exception:
        pass
    return findings


async def run_tech_detect(client: AsyncHTTPClient, domain: str) -> list[Finding]:
    findings: list[Finding] = []
    url = f"https://{domain}"

    try:
        html = await client.fetch_text(url)
        soup = BeautifulSoup(html, "lxml")

        generators = soup.find_all("meta", attrs={"name": "generator"})
        for g in generators:
            findings.append(Finding(
                type=FindingType.TECH_STACK,
                name="CMS Detected",
                severity=Severity.INFO,
                value=domain,
                description=f"Generator meta: {g.get('content', '')}",
                source="tech.html_meta",
            ))

        scripts = soup.find_all("script", src=True)
        known_patterns = {
            "react": "React",
            "angular": "Angular",
            "vue": "Vue.js",
            "jquery": "jQuery",
            "next": "Next.js",
            "nuxt": "Nuxt.js",
            "gatsby": "Gatsby",
            "django": "Django",
            "laravel": "Laravel",
            "wordpress": "WordPress",
            "wp-": "WordPress",
            "shopify": "Shopify",
            "cloudflare": "Cloudflare",
        }
        html_lower = html.lower()
        detected = set()
        for pattern, tech in known_patterns.items():
            if pattern in html_lower:
                detected.add(tech)

        for tech in sorted(detected):
            findings.append(Finding(
                type=FindingType.TECH_STACK,
                name=f"Technology: {tech}",
                severity=Severity.INFO,
                value=domain,
                source="tech.html_heuristic",
            ))
    except Exception:
        pass

    return findings


async def run_securitytrails(client: AsyncHTTPClient, domain: str, api_key: str) -> list[dict]:
    if not api_key:
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    try:
        data = await client.fetch_json(url, headers=headers)
        subdomains = data.get("subdomains", [])
        return [{"subdomain": f"{s}.{domain}", "source": "securitytrails"} for s in subdomains]
    except Exception:
        return []


async def run_virustotal(client: AsyncHTTPClient, domain: str, api_key: str) -> list[dict]:
    if not api_key:
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": api_key}
    try:
        data = await client.fetch_json(url, headers=headers)
        subdomains = []
        for item in data.get("data", []):
            subdomains.append({"subdomain": item.get("id", ""), "source": "virustotal"})
        return subdomains
    except Exception:
        return []


async def run_passive_phase(
    targets: list[Target],
    config: DORAConfig,
    findings: list[Finding],
):
    async with AsyncHTTPClient(config) as client:
        for target in targets:
            if not target.domain:
                continue
            domain = target.domain
            results: list[Finding] = []

            crt = await run_crtsh(client, domain)
            for entry in crt:
                results.append(Finding(
                    type=FindingType.SUBDOMAIN,
                    name="Subdomain (crt.sh)",
                    severity=Severity.INFO,
                    value=entry["subdomain"],
                    source=entry["source"],
                ))

            wayback = await run_wayback(client, domain)
            for entry in wayback:
                results.append(Finding(
                    type=FindingType.SUBDOMAIN,
                    name="Subdomain (Wayback)",
                    severity=Severity.INFO,
                    value=entry["subdomain"],
                    source=entry["source"],
                ))

            st_key = config.api_key_securitytrails
            if st_key:
                st = await run_securitytrails(client, domain, st_key)
                for entry in st:
                    results.append(Finding(
                        type=FindingType.SUBDOMAIN,
                        name="Subdomain (SecurityTrails)",
                        severity=Severity.INFO,
                        value=entry["subdomain"],
                        source=entry["source"],
                    ))

            vt_key = config.api_key_virustotal
            if vt_key:
                vt = await run_virustotal(client, domain, vt_key)
                for entry in vt:
                    results.append(Finding(
                        type=FindingType.SUBDOMAIN,
                        name="Subdomain (VirusTotal)",
                        severity=Severity.INFO,
                        value=entry["subdomain"],
                        source=entry["source"],
                    ))

            dns_findings = await run_dns_enum(domain)
            results.extend(dns_findings)

            zt_findings = await check_zone_transfer(domain)
            results.extend(zt_findings)

            tech_findings = await run_tech_detect(client, domain)
            results.extend(tech_findings)

            findings.extend(results)
