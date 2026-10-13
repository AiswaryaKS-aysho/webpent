from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_ORDER = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


@dataclass
class Finding:
    probe: str
    severity: Severity
    title: str
    url: str
    param: str = ""
    evidence: str = ""
    payload: str = ""
    remediation: str = ""
    confidence: str = "medium"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def sort_key(self) -> int:
        return _ORDER[self.severity]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    probes_run: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key, reverse=True)

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "probes_run": self.probes_run,
            "summary": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }
