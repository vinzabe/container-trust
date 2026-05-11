"""Operator-defined trust policy and gate evaluator.

The risk model produces a score; this module produces a *decision*.
Decisions are PASS, WARN, FAIL with a list of human-readable
violations.  The policy is intentionally simple so it can sit in CI
configuration without rule-engine sprawl.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence

from .findings import ScanReport, Severity


class PolicyDecision(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class PolicyViolation:
    code: str
    message: str
    severity: Severity = Severity.HIGH

    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
        }


@dataclass
class Policy:
    """Operator policy.

    * ``max_severity`` -- any finding at-or-above this severity is a FAIL
    * ``max_critical`` / ``max_high`` -- count gates
    * ``allow_unfixed`` -- if False, any unfixed CVE at-or-above
      ``max_severity`` triggers FAIL
    * ``banned_packages`` -- substring match on `pkg_name`
    * ``banned_licenses`` -- exact match on license name (e.g. "AGPL-3.0")
    * ``deny_secrets`` -- if True, *any* secret finding is a FAIL
    * ``score_warn`` / ``score_fail`` -- numeric score gates from RiskModel
    """

    max_severity: Severity = Severity.CRITICAL
    max_critical: int = 0
    max_high: int = 5
    allow_unfixed: bool = False
    banned_packages: Sequence[str] = field(default_factory=list)
    banned_licenses: Sequence[str] = field(default_factory=list)
    deny_secrets: bool = True
    score_warn: float = 35.0
    score_fail: float = 70.0


@dataclass
class _Eval:
    decision: PolicyDecision
    violations: List[PolicyViolation]


def evaluate_policy(
    report: ScanReport, policy: Policy, score: Optional[float] = None
) -> _Eval:
    violations: List[PolicyViolation] = []

    counts = report.severity_counts()
    if counts.get(Severity.CRITICAL.value, 0) > policy.max_critical:
        violations.append(PolicyViolation(
            code="CRITICAL_OVER_LIMIT",
            message=(
                f"{counts[Severity.CRITICAL.value]} CRITICAL findings "
                f"exceed limit of {policy.max_critical}"
            ),
            severity=Severity.CRITICAL,
        ))
    if counts.get(Severity.HIGH.value, 0) > policy.max_high:
        violations.append(PolicyViolation(
            code="HIGH_OVER_LIMIT",
            message=(
                f"{counts[Severity.HIGH.value]} HIGH findings exceed "
                f"limit of {policy.max_high}"
            ),
            severity=Severity.HIGH,
        ))

    # any finding at or above max_severity that is unfixed
    if not policy.allow_unfixed:
        threshold = policy.max_severity.rank
        unfixed = [
            f for f in report.findings
            if f.severity.rank >= threshold and not f.is_fixable()
        ]
        if unfixed:
            violations.append(PolicyViolation(
                code="UNFIXED_HIGH_SEVERITY",
                message=(
                    f"{len(unfixed)} finding(s) at >= {policy.max_severity.value} "
                    "have no fixed version"
                ),
                severity=Severity.HIGH,
            ))

    # banned packages -- substring match (case-insensitive) on pkg_name
    if policy.banned_packages:
        banned_lc = [b.lower() for b in policy.banned_packages]
        hit_pkgs = sorted({
            f.pkg_name for f in report.findings
            if any(b in f.pkg_name.lower() for b in banned_lc)
        })
        if hit_pkgs:
            violations.append(PolicyViolation(
                code="BANNED_PACKAGE",
                message=f"banned packages present: {', '.join(hit_pkgs)}",
                severity=Severity.HIGH,
            ))

    # banned licenses -- exact match
    if policy.banned_licenses:
        banned_lic = {l.lower() for l in policy.banned_licenses}
        hit_lic = sorted({
            l.license for l in report.licenses
            if l.license.lower() in banned_lic
        })
        if hit_lic:
            violations.append(PolicyViolation(
                code="BANNED_LICENSE",
                message=f"banned licenses present: {', '.join(hit_lic)}",
                severity=Severity.HIGH,
            ))

    # secrets
    if policy.deny_secrets and report.secrets:
        violations.append(PolicyViolation(
            code="SECRET_LEAK",
            message=f"{len(report.secrets)} secret(s) detected in artefact",
            severity=Severity.CRITICAL,
        ))

    # score gates
    if score is not None and score >= policy.score_fail:
        violations.append(PolicyViolation(
            code="RISK_SCORE_FAIL",
            message=f"risk score {score:.2f} >= fail threshold {policy.score_fail}",
            severity=Severity.HIGH,
        ))

    # decision = highest of the violation severities, then fold to PASS/WARN/FAIL
    if any(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in violations):
        decision = PolicyDecision.FAIL
    elif violations or (score is not None and score >= policy.score_warn):
        decision = PolicyDecision.WARN
    else:
        decision = PolicyDecision.PASS
    return _Eval(decision=decision, violations=violations)
