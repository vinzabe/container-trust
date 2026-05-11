"""Normalised datamodel for trivy findings.

Trivy's JSON schema changes across minor versions; we project it into a
stable shape so the rest of the pipeline (risk model, policy, advisor)
does not have to chase upstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self.value]

    @classmethod
    def from_str(cls, raw: Any) -> "Severity":
        if raw is None:
            return cls.UNKNOWN
        s = str(raw).upper().strip()
        if s in _SEV_RANK:
            return cls(s)
        return cls.UNKNOWN


_SEV_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    """One vulnerability against one (pkg, target) location."""

    cve_id: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: Severity
    title: str
    target: str
    primary_url: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    status: Optional[str] = None  # "fixed" / "affected" / "will_not_fix" / ...

    def is_fixable(self) -> bool:
        return bool(self.fixed_version) and self.fixed_version != self.installed_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "pkg_name": self.pkg_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity.value,
            "title": self.title,
            "target": self.target,
            "primary_url": self.primary_url,
            "cvss_score": self.cvss_score,
            "status": self.status,
        }


@dataclass
class SecretFinding:
    """A leaked credential pattern detected in the artefact."""

    rule_id: str
    category: str
    severity: Severity
    title: str
    target: str
    start_line: int
    end_line: int
    match: str  # the raw matched line (already truncated by trivy)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "target": self.target,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "match": self.match,
        }


@dataclass
class LicenseFinding:
    pkg_name: str
    license: str
    severity: Severity
    target: str
    category: str = "package-license"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pkg_name": self.pkg_name,
            "license": self.license,
            "severity": self.severity.value,
            "target": self.target,
            "category": self.category,
        }


@dataclass
class MisconfigFinding:
    """Trivy 'misconfiguration' (e.g. Dockerfile USER root)."""

    rule_id: str
    severity: Severity
    title: str
    target: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "target": self.target,
            "message": self.message,
        }


@dataclass
class ScanReport:
    artifact_name: str
    artifact_type: str
    schema_version: int
    findings: List[Finding] = field(default_factory=list)
    secrets: List[SecretFinding] = field(default_factory=list)
    licenses: List[LicenseFinding] = field(default_factory=list)
    misconfigs: List[MisconfigFinding] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    # ---- summary helpers ------------------------------------------------

    def severity_counts(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def fixable_count(self) -> int:
        return sum(1 for f in self.findings if f.is_fixable())

    def packages(self) -> List[str]:
        return sorted({f.pkg_name for f in self.findings})

    def cves(self) -> List[str]:
        return sorted({f.cve_id for f in self.findings if f.cve_id})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_name": self.artifact_name,
            "artifact_type": self.artifact_type,
            "schema_version": self.schema_version,
            "severity_counts": self.severity_counts(),
            "fixable_count": self.fixable_count(),
            "findings": [f.to_dict() for f in self.findings],
            "secrets": [s.to_dict() for s in self.secrets],
            "licenses": [l.to_dict() for l in self.licenses],
            "misconfigs": [m.to_dict() for m in self.misconfigs],
        }
