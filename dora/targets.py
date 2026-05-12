from __future__ import annotations

from dora.models import Target


def parse_target(raw: str) -> Target:
    return Target(raw=raw)


def parse_targets(raw_targets: list[str]) -> list[Target]:
    return [parse_target(t) for t in raw_targets]
