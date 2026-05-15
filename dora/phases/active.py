from __future__ import annotations

import asyncio
import socket
from typing import Optional

from dora.config import DORAConfig
from dora.models import Finding, FindingType, Severity, Target
from dora.utils.http import AsyncHTTPClient


def _parse_ports(port_str: str) -> list[int]:
    ports: list[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return ports


async def _tcp_scan(target_host: str, port: int, timeout: float = 3.0) -> Optional[int]:
    try:
        _, _, ips = socket.gethostbyname_ex(target_host)
        ip = ips[0]
    except Exception:
        try:
            ip = socket.gethostbyname(target_host)
        except Exception:
            return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None


async def _banner_grab(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        ip = ips[0]
    except Exception:
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in (80, 8080, 443, 8443):
            sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner if banner else None
    except Exception:
        return None


_KNOWN_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9000: "PHP-FPM", 27017: "MongoDB",
}


async def run_port_scan(target: Target, config: DORAConfig) -> list[Finding]:
    findings: list[Finding] = []
    host = target.domain or target.ip
    if not host:
        return findings

    port_str = config.port_scan_ports
    ports = _parse_ports(port_str)

    console_print = None
    try:
        from rich.console import Console
        console_print = Console().print
    except ImportError:
        pass

    if console_print:
        console_print(f"[cyan]Scanning {len(ports)} ports on {host}...[/]")

    scan_tasks = [_tcp_scan(host, p, timeout=float(config.scan_timeout)) for p in ports]
    batch_size = 50
    open_ports: list[int] = []

    for i in range(0, len(scan_tasks), batch_size):
        batch = scan_tasks[i:i + batch_size]
        results = await asyncio.gather(*batch)
        for r in results:
            if r is not None:
                open_ports.append(r)
        await asyncio.sleep(0.05)

    if console_print:
        console_print(f"[green]Found {len(open_ports)} open ports[/]")

    for port in sorted(open_ports):
        service = _KNOWN_SERVICES.get(port, "Unknown")
        banner = await _banner_grab(host, port)
        desc = f"Port {port}/{service} is open"
        if banner:
            desc += f"\nBanner: {banner[:200]}"
        findings.append(Finding(
            type=FindingType.OPEN_PORT,
            name=f"Open Port {port}",
            severity=Severity.MEDIUM if port in (22, 3389, 3306, 5432, 6379, 27017, 1433) else Severity.LOW,
            value=f"{host}:{port} ({service})",
            description=desc,
            evidence=banner[:500] if banner else "",
            source="port_scan.tcp",
            extra={"port": port, "service": service, "banner": banner or ""},
        ))

    target.ports = sorted(open_ports)
    return findings


async def run_http_probe(target: Target, config: DORAConfig) -> list[Finding]:
    findings: list[Finding] = []
    host = target.domain or target.ip
    if not host:
        return findings

    ports_to_probe = target.ports or [80, 443, 8080, 8443]

    async with AsyncHTTPClient(config) as client:
        for port in ports_to_probe:
            for proto in ("https", "http"):
                url = f"{proto}://{host}:{port}"
                try:
                    result_url, status, headers = await client.probe(url)
                    if status and status > 0:
                        server = headers.get("server", headers.get("Server", "Unknown"))
                        title = ""
                        try:
                            text = await client.fetch_text(url)
                            from bs4 import BeautifulSoup
                            soup = BeautifulSoup(text, "lxml")
                            t = soup.find("title")
                            if t:
                                title = t.text.strip()[:100]
                        except Exception:
                            pass

                        findings.append(Finding(
                            type=FindingType.OPEN_PORT,
                            name=f"HTTP Service on {port}",
                            severity=Severity.INFO,
                            value=url,
                            description=f"Status: {status}, Server: {server}"
                                        + (f", Title: {title}" if title else ""),
                            evidence=f"Status: {status}, Headers: {dict(headers)}",
                            source="port_scan.http_probe",
                            extra={"url": url, "status": status, "server": server},
                        ))
                        break
                except Exception:
                    continue

    return findings


async def run_active_phase(
    targets: list[Target],
    config: DORAConfig,
    findings: list[Finding],
):
    for target in targets:
        port_findings = await run_port_scan(target, config)
        findings.extend(port_findings)

        http_findings = await run_http_probe(target, config)
        findings.extend(http_findings)
