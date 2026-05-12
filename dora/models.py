from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    OPEN_PORT = "open_port"
    SUBDOMAIN = "subdomain"
    DIRECTORY = "directory"
    API_ENDPOINT = "api_endpoint"
    PARAMETER = "parameter"
    JS_ENDPOINT = "js_endpoint"
    SECRET = "secret"
    CVE = "cve"
    SSL_ISSUE = "ssl_issue"
    MISSING_HEADER = "missing_header"
    CORS_ISSUE = "cors_issue"
    TECH_STACK = "tech_stack"
    DNS_RECORD = "dns_record"
    OSINT = "osint"


@dataclass
class Finding:
    type: FindingType
    name: str
    severity: Severity
    value: str
    description: str = ""
    evidence: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "name": self.name,
            "severity": self.severity.value,
            "value": self.value,
            "description": self.description,
            "evidence": self.evidence,
            "source": self.source,
            "extra": self.extra,
        }


@dataclass
class Target:
    raw: str
    domain: Optional[str] = None
    ip: Optional[str] = None
    cidr: Optional[str] = None
    ports: list[int] = field(default_factory=list)

    def __post_init__(self):
        self._parse()

    def _parse(self):
        if self.raw.startswith("http://") or self.raw.startswith("https://"):
            from urllib.parse import urlparse
            parsed = urlparse(self.raw)
            hostname = parsed.hostname or self.raw
        else:
            hostname = self.raw.split("/")[0].split(":")[0]

        try:
            ipaddress.ip_address(hostname)
            self.ip = hostname
        except ValueError:
            pass

        try:
            ipaddress.ip_network(hostname, strict=False)
            self.cidr = hostname
            return
        except ValueError:
            pass

        domain_re = re.compile(
            r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        )
        if domain_re.match(hostname):
            self.domain = hostname

    @property
    def base_url(self) -> str:
        if self.domain:
            return f"https://{self.domain}"
        if self.ip:
            return f"http://{self.ip}"
        if self.cidr:
            return self.cidr
        return self.raw

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "domain": self.domain,
            "ip": self.ip,
            "cidr": self.cidr,
            "ports": self.ports,
        }


@dataclass
class ScanResult:
    target: Target
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    findings: list[Finding] = field(default_factory=list)
    phases_executed: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity.value, []).append(f)
        return result

    def by_type(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.type.value, []).append(f)
        return result

    def summary(self) -> dict:
        return {
            "target": self.target.to_dict(),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_findings": len(self.findings),
            "phases_executed": self.phases_executed,
            "by_severity": {k: len(v) for k, v in self.by_severity().items()},
            "by_type": {k: len(v) for k, v in self.by_type().items()},
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
