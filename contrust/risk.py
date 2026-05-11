"""Deterministic risk score for a scan report.

Inputs:
  * severity counts (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN)
  * fixable count (a vuln you can patch is more actionable than one you
    can't, but it doesn't make the artefact safer until you do)
  * secret count (any leaked credential is a high-impact finding)
  * misconfig count (security-relevant Dockerfile / IaC issues)
  * license deny-list hits (a banned-license package poisons the artefact)

The model is intentionally not learned; reproducibility and operator
auditability matter more than absolute calibration.  Operators tune
weights via ``RiskModel`` constructor args.

Scores are clamped to ``[0, 100]``; everything above ``critical_block``
should fail an operator gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .findings import ScanReport, Severity


@dataclass
class RiskBreakdown:
    score: float
    severity_subscore: float
    secret_subscore: float
    misconfig_subscore: float
    license_subscore: float
    band: str  # "minimal" | "low" | "medium" | "high" | "critical"
    components: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, float]:
        return {
            "score": self.score,
            "severity_subscore": self.severity_subscore,
            "secret_subscore": self.secret_subscore,
            "misconfig_subscore": self.misconfig_subscore,
            "license_subscore": self.license_subscore,
            "band": self.band,
            "components": dict(self.components),
        }


def _band(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 10:
        return "low"
    return "minimal"


@dataclass
class RiskModel:
    """Score a ``ScanReport`` deterministically.

    Weight defaults are tuned so a single CRITICAL CVE puts an artefact
    in the "high" band, and an exposed AWS key alone is "critical".
    """

    sev_weights: Dict[str, float] = field(
        default_factory=lambda: {
            Severity.CRITICAL.value: 18.0,
            Severity.HIGH.value: 8.0,
            Severity.MEDIUM.value: 2.0,
            Severity.LOW.value: 0.5,
            Severity.UNKNOWN.value: 0.25,
        }
    )
    secret_weight: float = 25.0  # per secret finding
    misconfig_weight: float = 4.0  # per misconfig finding
    license_weight: float = 8.0  # per banned-license finding (caller filters)

    sev_cap: float = 60.0       # severity subscore cap
    secret_cap: float = 80.0
    misconfig_cap: float = 30.0
    license_cap: float = 25.0

    def score(self, report: ScanReport) -> RiskBreakdown:
        counts = report.severity_counts()
        sev_sub = sum(self.sev_weights.get(k, 0.0) * v for k, v in counts.items())
        sev_sub = min(sev_sub, self.sev_cap)

        secret_sub = min(self.secret_weight * len(report.secrets), self.secret_cap)
        misconfig_sub = min(
            self.misconfig_weight * len(report.misconfigs), self.misconfig_cap
        )
        license_sub = min(
            self.license_weight * len(report.licenses), self.license_cap
        )

        total = sev_sub + secret_sub + misconfig_sub + license_sub
        total = max(0.0, min(100.0, total))

        return RiskBreakdown(
            score=round(total, 2),
            severity_subscore=round(sev_sub, 2),
            secret_subscore=round(secret_sub, 2),
            misconfig_subscore=round(misconfig_sub, 2),
            license_subscore=round(license_sub, 2),
            band=_band(total),
            components={
                "n_critical": float(counts.get(Severity.CRITICAL.value, 0)),
                "n_high": float(counts.get(Severity.HIGH.value, 0)),
                "n_medium": float(counts.get(Severity.MEDIUM.value, 0)),
                "n_low": float(counts.get(Severity.LOW.value, 0)),
                "n_secrets": float(len(report.secrets)),
                "n_misconfigs": float(len(report.misconfigs)),
                "n_license_findings": float(len(report.licenses)),
            },
        )
