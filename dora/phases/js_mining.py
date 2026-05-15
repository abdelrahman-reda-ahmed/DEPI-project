from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from dora.config import DORAConfig
from dora.models import Finding, FindingType, Severity, Target
from dora.utils.http import AsyncHTTPClient


_JS_URL_RE = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
_URL_IN_JS_RE = re.compile(r'(?:https?://[^\s"\'<>]+)')
_API_PATH_RE = re.compile(r'["\'](/?(?:api|v[1-9]|rest|graphql|swagger)/[^"\' ]+)["\']', re.I)

_SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (r'(?i)(?:aws_access_key_id|AWS_ACCESS_KEY)[=:]["\']?([A-Z0-9]{16,})["\']?', "AWS Access Key ID", Severity.CRITICAL),
    (r'(?i)(?:aws_secret_access_key|AWS_SECRET_KEY)[=:]["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Access Key", Severity.CRITICAL),
    (r'(?i)(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}', "GitHub Token", Severity.CRITICAL),
    (r'(?i)(?:sk_live_|pk_live_)[A-Za-z0-9]{20,}', "Stripe Live Key", Severity.CRITICAL),
    (r'(?i)(?:sk_test_|pk_test_)[A-Za-z0-9]{20,}', "Stripe Test Key", Severity.HIGH),
    (r'(?i)AIza[0-9A-Za-z_-]{35}', "Google API Key", Severity.HIGH),
    (r'(?i)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    (r'(?i)-----BEGIN CERTIFICATE-----', "Certificate", Severity.MEDIUM),
    (r'(?i)(?:slack|discord)\.com/api/.*hook', "Webhook URL", Severity.CRITICAL),
    (r'(?i)token[=:]["\']?([A-Za-z0-9._-]{20,})["\']?', "Generic Token/Secret", Severity.HIGH),
    (r'(?i)(?:password|passwd|pwd)[=:]["\']?([^"\'&\s]{6,})["\']?', "Password", Severity.CRITICAL),
    (r'(?i)(?:api[_-]?key|apikey)[=:]["\']?([A-Za-z0-9._-]{10,})["\']?', "API Key", Severity.HIGH),
    (r'(?i)(?:secret)[=:]["\']?([A-Za-z0-9._-]{10,})["\']?', "Generic Secret", Severity.HIGH),
    (r'(?:mongodb(?:\+srv)?://)[^\s"\'<>]+', "MongoDB Connection String", Severity.CRITICAL),
    (r'(?:postgres(?:ql)?://)[^\s"\'<>]+', "PostgreSQL Connection String", Severity.CRITICAL),
    (r'(?:mysql://)[^\s"\'<>]+', "MySQL Connection String", Severity.CRITICAL),
    (r'(?:redis://)[^\s"\'<>]+', "Redis Connection String", Severity.CRITICAL),
]


async def _crawl_js_urls(client: AsyncHTTPClient, url: str, domain: str) -> set[str]:
    js_urls: set[str] = set()
    try:
        html = await client.fetch_text(url)
        soup = BeautifulSoup(html, "lxml")
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if src.endswith(".js") or ".js?" in src:
                full = urljoin(url, src)
                parsed = urlparse(full)
                if domain in parsed.hostname or not parsed.hostname:
                    js_urls.add(full)

        for match in _JS_URL_RE.finditer(html):
            src = match.group(1)
            full = urljoin(url, src)
            js_urls.add(full)
    except Exception:
        pass

    sourcemap_urls: set[str] = set()
    for js in js_urls:
        try:
            text = await client.fetch_text(js)
            sourcemap_match = re.search(r'//# sourceMappingURL=(\S+)', text)
            if sourcemap_match:
                sm = urljoin(js, sourcemap_match.group(1))
                sourcemap_urls.add(sm)
        except Exception:
            pass

    return js_urls | sourcemap_urls


async def _analyze_js_content(client: AsyncHTTPClient, js_url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = await client.fetch_text(js_url)
    except Exception:
        return findings

    urls = _URL_IN_JS_RE.findall(text)
    for url in urls[:20]:
        findings.append(Finding(
            type=FindingType.JS_ENDPOINT,
            name="URL in JS",
            severity=Severity.INFO,
            value=url,
            description=f"Found in {js_url}",
            source="js_analysis.url_extract",
            extra={"js_url": js_url},
        ))

    api_paths = _API_PATH_RE.findall(text)
    for path in set(api_paths[:20]):
        findings.append(Finding(
            type=FindingType.API_ENDPOINT,
            name="API Path in JS",
            severity=Severity.MEDIUM,
            value=path,
            description=f"Found in {js_url}",
            source="js_analysis.api_extract",
            extra={"js_url": js_url},
        ))

    for pattern, secret_name, severity in _SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            matched_val = match.group(0) if pattern.startswith("(?:") else match.group(0)
            findings.append(Finding(
                type=FindingType.SECRET,
                name=secret_name,
                severity=severity,
                value=matched_val[:80] + "..." if len(matched_val) > 80 else matched_val,
                description=f"Secret found in {js_url}",
                evidence=f"Match: {matched_val[:100]}",
                source="js_analysis.secret_detection",
                extra={"js_url": js_url, "pattern": pattern},
            ))

    return findings


async def run_js_mining_phase(
    targets: list[Target],
    config: DORAConfig,
    findings: list[Finding],
):
    async with AsyncHTTPClient(config) as client:
        for target in targets:
            domain = target.domain
            if not domain:
                continue

            base = target.base_url

            js_urls = await _crawl_js_urls(client, base, domain)
            for js_url in js_urls:
                findings.append(Finding(
                    type=FindingType.JS_ENDPOINT,
                    name="JavaScript File",
                    severity=Severity.INFO,
                    value=js_url,
                    description=f"JavaScript file discovered",
                    source="js_mining.crawl",
                ))

            js_tasks = [_analyze_js_content(client, js) for js in js_urls]
            batch_size = 5
            for i in range(0, len(js_tasks), batch_size):
                batch = js_tasks[i:i + batch_size]
                results = await asyncio.gather(*batch)
                for r in results:
                    findings.extend(r)
                await asyncio.sleep(0.05)
