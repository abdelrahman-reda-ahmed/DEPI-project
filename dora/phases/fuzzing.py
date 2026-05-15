from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from dora.config import DORAConfig
from dora.models import Finding, FindingType, Severity, Target
from dora.utils.http import AsyncHTTPClient


def _load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


async def dir_fuzz_target(
    client: AsyncHTTPClient,
    base_url: str,
    wordlist_path: Path,
    extensions: list[str] = None,
    max_concurrent: int = 20,
    min_response_size: int = 100,
) -> list[Finding]:
    findings: list[Finding] = []
    entries = _load_wordlist(wordlist_path)
    if not entries:
        return findings

    sem = asyncio.Semaphore(max_concurrent)

    async def check_path(path: str) -> Optional[Finding]:
        async with sem:
            for ext in (extensions or ["", "/"]):
                full_path = path + ext if ext != "/" else path + "/"
                url = base_url.rstrip("/") + "/" + full_path.lstrip("/")
                try:
                    resp = await client.get(url)
                    status = resp.status_code
                    content_len = len(resp.content)
                    if content_len < min_response_size:
                        return None
                    if status in (200, 201, 204, 301, 302, 307, 308, 401, 403, 500):
                        return Finding(
                            type=FindingType.DIRECTORY,
                            name=f"Directory: {full_path}",
                            severity=Severity.MEDIUM if status == 403 else (
                                Severity.HIGH if "admin" in full_path.lower() or "api" in full_path.lower() or ".git" in full_path or ".env" in full_path else Severity.LOW
                            ),
                            value=url,
                            description=f"Status: {status}, Size: {content_len}",
                            evidence=f"HTTP {status} ({content_len} bytes)",
                            source="fuzzing.directory",
                            extra={"path": full_path, "status": status, "size": content_len},
                        )
                except Exception:
                    pass
        return None

    tasks = [check_path(e) for e in entries]
    batch_size = max_concurrent * 2
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        results = await asyncio.gather(*batch)
        for r in results:
            if r:
                findings.append(r)
        await asyncio.sleep(0.02)

    return findings


async def fuzz_api_endpoints(
    client: AsyncHTTPClient,
    base_url: str,
    domain: str,
) -> list[Finding]:
    findings: list[Finding] = []

    api_paths = [
        "api", "api/v1", "api/v2", "api/v3", "api/rest", "api/graphql",
        "graphql", "swagger", "swagger/v1", "swagger-ui", "swagger-ui.html",
        "api-docs", "openapi.json", "docs", "documentation",
        "api/swagger", "api/docs", "api/openapi",
        "v1", "v2", "rest", "api/health", "api/status",
        "grpc", "soap", "ws", "websocket",
    ]

    sem = asyncio.Semaphore(10)

    async def check_api(path: str) -> Optional[Finding]:
        async with sem:
            url = base_url.rstrip("/") + "/" + path
            try:
                resp = await client.get(url)
                status = resp.status_code
                if status in (200, 201, 401, 403, 405, 500):
                    content_type = resp.headers.get("content-type", "")
                    return Finding(
                        type=FindingType.API_ENDPOINT,
                        name=f"API Endpoint: {path}",
                        severity=Severity.MEDIUM,
                        value=url,
                        description=f"Status: {status}, Content-Type: {content_type}",
                        evidence=f"HTTP {status}",
                        source="fuzzing.api",
                        extra={"path": path, "status": status, "content_type": content_type},
                    )
            except Exception:
                pass
        return None

    tasks = [check_api(p) for p in api_paths]
    results = await asyncio.gather(*tasks)
    for r in results:
        if r:
            findings.append(r)

    return findings


async def fuzz_parameters(
    client: AsyncHTTPClient,
    base_url: str,
    endpoint: str = "",
) -> list[Finding]:
    findings: list[Finding] = []

    common_params = [
        "id", "q", "s", "search", "query", "page", "limit", "offset",
        "sort", "order", "filter", "type", "category", "tag", "lang",
        "callback", "format", "file", "path", "url", "redirect",
        "next", "prev", "token", "key", "api_key", "apikey", "secret",
        "debug", "test", "admin", "action", "mode", "method", "cmd",
        "exec", "command", "db", "host", "port", "user", "pass",
        "password", "email", "name", "username", "uid",
    ]

    target_url = base_url.rstrip("/") + "/" + endpoint.lstrip("/") if endpoint else base_url.rstrip("/")
    sem = asyncio.Semaphore(15)

    async def check_param(param: str) -> Optional[Finding]:
        async with sem:
            for method in ("GET", "POST"):
                try:
                    sep = "?" if "?" not in target_url else "&"
                    url = f"{target_url}{sep}{param}=test"
                    if method == "GET":
                        resp = await client.get(url)
                    else:
                        resp = await client.post(url)
                    status = resp.status_code
                    content_len = len(resp.content)
                    if status not in (404, 0) and content_len > 0:
                        return Finding(
                            type=FindingType.PARAMETER,
                            name=f"Parameter: {param}",
                            severity=Severity.INFO,
                            value=f"{url} [{status}]",
                            description=f"Accepted parameter '{param}' on {method} {target_url}",
                            evidence=f"HTTP {status} ({content_len} bytes)",
                            source="fuzzing.parameter",
                            extra={"parameter": param, "method": method, "status": status},
                        )
                except Exception:
                    pass
        return None

    tasks = [check_param(p) for p in common_params]
    batch_size = 30
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        results = await asyncio.gather(*batch)
        for r in results:
            if r:
                findings.append(r)
        await asyncio.sleep(0.02)

    return findings


async def _fuzz_single_target(
    client: AsyncHTTPClient,
    base_url: str,
    domain: Optional[str],
    config: DORAConfig,
    findings: list[Finding],
):
    dir_findings = await dir_fuzz_target(
        client, base_url, config.wordlist_directories,
        max_concurrent=config.scan_threads,
        min_response_size=config.min_response_size,
    )
    findings.extend(dir_findings)

    if domain:
        api_findings = await fuzz_api_endpoints(client, base_url, domain)
        findings.extend(api_findings)

    param_findings = await fuzz_parameters(client, base_url)
    findings.extend(param_findings)


async def run_fuzzing_phase(
    targets: list[Target],
    config: DORAConfig,
    findings: list[Finding],
):
    async with AsyncHTTPClient(config) as client:
        for target in targets:
            await _fuzz_single_target(client, target.base_url, target.domain, config, findings)

        subdomains = list({f.value for f in findings if f.type == FindingType.SUBDOMAIN})
        for sub in subdomains:
            base_url = f"https://{sub}" if not sub.startswith("http") else sub
            await _fuzz_single_target(client, base_url, sub, config, findings)
