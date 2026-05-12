from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from dora.config import DORAConfig
from dora.models import Finding, FindingType, Severity, Target
from dora.utils.http import AsyncHTTPClient


async def check_ssl_tls(host: str, port: int = 443) -> list[Finding]:
    findings: list[Finding] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        sock = socket.create_connection((host, port), timeout=10)
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            version = ssock.version()

            if cert:
                not_after = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")

                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days

                    if days_left < 0:
                        findings.append(Finding(
                            type=FindingType.SSL_ISSUE,
                            name="SSL Certificate Expired",
                            severity=Severity.CRITICAL,
                            value=host,
                            description=f"Certificate expired {abs(days_left)} days ago",
                            evidence=f"NotAfter: {not_after}",
                            source="ssl.check",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            type=FindingType.SSL_ISSUE,
                            name="SSL Certificate Expiring Soon",
                            severity=Severity.HIGH,
                            value=host,
                            description=f"Certificate expires in {days_left} days",
                            evidence=f"NotAfter: {not_after}",
                            source="ssl.check",
                        ))
                except (ValueError, TypeError):
                    pass

                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "")
                san = cert.get("subjectAltName", [])
                san_domains = [v for k, v in san if k == "DNS"]

                if host not in san_domains and host != cn:
                    findings.append(Finding(
                        type=FindingType.SSL_ISSUE,
                        name="SSL Hostname Mismatch",
                        severity=Severity.HIGH,
                        value=host,
                        description=f"Certificate CN={cn} doesn't match {host}",
                        source="ssl.check",
                    ))

            weak_versions = {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}
            if version and version in weak_versions:
                findings.append(Finding(
                    type=FindingType.SSL_ISSUE,
                    name=f"Weak TLS Version: {version}",
                    severity=Severity.HIGH,
                    value=host,
                    description=f"Server supports deprecated {version}",
                    source="ssl.check",
                ))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            type=FindingType.SSL_ISSUE,
            name="SSL Certificate Error",
            severity=Severity.HIGH,
            value=host,
            description=str(e),
            source="ssl.check",
        ))
    except Exception:
        pass

    return findings


async def check_security_headers(client: AsyncHTTPClient, url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = await client.get(url)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        security_checks = {
            "strict-transport-security": ("Missing HSTS Header", Severity.MEDIUM,
                                          "Add Strict-Transport-Security header"),
            "content-security-policy": ("Missing CSP Header", Severity.MEDIUM,
                                        "Add Content-Security-Policy to prevent XSS"),
            "x-content-type-options": ("Missing X-Content-Type-Options Header", Severity.LOW,
                                       "Add X-Content-Type-Options: nosniff"),
            "x-frame-options": ("Missing X-Frame-Options Header", Severity.LOW,
                                "Add X-Frame-Options: DENY or SAMEORIGIN"),
            "x-xss-protection": ("Missing X-XSS-Protection Header", Severity.LOW,
                                 "Add X-XSS-Protection: 1; mode=block"),
            "referrer-policy": ("Missing Referrer-Policy Header", Severity.LOW,
                                "Add Referrer-Policy header"),
        }

        for header, (name, severity, fix) in security_checks.items():
            if header not in headers:
                findings.append(Finding(
                    type=FindingType.MISSING_HEADER,
                    name=name,
                    severity=severity,
                    value=url,
                    description=fix,
                    source="security_headers.check",
                ))

        server = headers.get("server", "")
        if server and server not in ("cloudflare", "nginx", "Apache"):
            findings.append(Finding(
                type=FindingType.OSINT,
                name=f"Server: {server}",
                severity=Severity.INFO,
                value=url,
                description=f"Server header reveals: {server}",
                source="security_headers.server",
            ))

        x_powered_by = headers.get("x-powered-by", "")
        if x_powered_by:
            findings.append(Finding(
                type=FindingType.OSINT,
                name=f"X-Powered-By: {x_powered_by}",
                severity=Severity.INFO,
                value=url,
                description=f"X-Powered-By reveals: {x_powered_by}",
                source="security_headers.server",
            ))

        cors_origin = headers.get("access-control-allow-origin", "")
        if cors_origin == "*":
            findings.append(Finding(
                type=FindingType.CORS_ISSUE,
                name="CORS Misconfiguration",
                severity=Severity.MEDIUM,
                value=url,
                description="Access-Control-Allow-Origin: * allows any origin",
                evidence="CORS is wide open",
                source="security_headers.cors",
            ))
        elif cors_origin and cors_origin != "null":
            findings.append(Finding(
                type=FindingType.CORS_ISSUE,
                name=f"CORS Origin: {cors_origin}",
                severity=Severity.INFO,
                value=url,
                source="security_headers.cors",
            ))

    except Exception:
        pass

    return findings


async def run_cve_check(target: Target, findings_so_far: list[Finding]) -> list[Finding]:
    cve_findings: list[Finding] = []

    service_versions: dict[str, str] = {}
    for f in findings_so_far:
        if f.type == FindingType.OPEN_PORT:
            banner = f.evidence or ""
            svc = f.extra.get("service", "")
            if banner and svc:
                service_versions[svc] = banner

    if not service_versions:
        return cve_findings

    try:
        async with AsyncHTTPClient.__new__(AsyncHTTPClient) as client:
            pass
    except Exception:
        pass

    return cve_findings


async def run_vuln_check_phase(
    targets: list[Target],
    config: DORAConfig,
    findings: list[Finding],
):
    async with AsyncHTTPClient(config) as client:
        for target in targets:
            host = target.domain or target.ip
            if not host:
                continue

            base = target.base_url

            header_findings = await check_security_headers(client, base)
            findings.extend(header_findings)

            if target.domain:
                ssl_findings = await check_ssl_tls(target.domain)
                findings.extend(ssl_findings)

            if target.ip:
                ssl_findings = await check_ssl_tls(target.ip)
                findings.extend(ssl_findings)

            for port in target.ports:
                if port in (443, 8443):
                    ssl_findings = await check_ssl_tls(host, port)
                    findings.extend(ssl_findings)

            cve_findings = await run_cve_check(target, findings)
            findings.extend(cve_findings)
