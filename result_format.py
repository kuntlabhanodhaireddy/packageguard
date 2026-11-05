"""Shared result format. Every module returns this shape, so the UI and agent can rely on it."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Verdict = Literal["Safe", "Caution", "Danger"]
Confidence = Literal["High", "Medium", "Low"]


@dataclass
class PackageResult:
    name: str
    version: str
    verdict: Verdict
    confidence: Confidence
    reasons: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    fix: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)
