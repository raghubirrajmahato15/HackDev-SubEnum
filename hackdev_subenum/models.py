"""Shared data models used across HackDev-SubEnum modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TakeoverFinding:
    """Evidence that a subdomain may be vulnerable to a CNAME-based takeover."""

    service: str
    cname_target: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "cname_target": self.cname_target,
            "evidence": self.evidence,
        }


@dataclass
class SubdomainResult:
    """A single enumerated subdomain and everything discovered about it."""

    subdomain: str
    ips: list[str] = field(default_factory=list)
    resolved: bool = False
    source: str = "active"  # "passive-crtsh" | "passive-otx" | "passive-wayback" | "active" | "mutation"
    cname: Optional[str] = None
    wildcard_filtered: bool = False
    takeover: Optional[TakeoverFinding] = None

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ips": self.ips,
            "resolved": self.resolved,
            "source": self.source,
            "cname": self.cname,
            "wildcard_filtered": self.wildcard_filtered,
            "takeover": self.takeover.to_dict() if self.takeover else None,
        }
