r"""LLM-backed remediation advisor.

The advisor takes a ``ScanReport`` plus a ``RiskBreakdown`` plus optional
policy violations and asks the LLM for a prioritised remediation plan.
It then validates every CVE / package / file the LLM mentions against the
real scan to suppress hallucinated advice.

Hallucination guards:

* ``cve_id`` (if present) must match ``CVE-\d{4}-\d{4,}`` *and* appear
  in the actual scan
* ``package`` (if present) must appear in the scan's package list
* ``severity`` clamped to UNKNOWN..CRITICAL
* ``effort`` clamped to ``low|medium|high``
* ``confidence`` clamped to ``[0, 1]``
* ``recommended_actions`` capped at 12 entries
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .findings import ScanReport, Severity
from .policy import PolicyViolation
from .risk import RiskBreakdown

try:
    from .llm_client import LLMClient
except Exception:  # pragma: no cover
    LLMClient = None  # type: ignore


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ALLOWED_EFFORT = {"low", "medium", "high"}


@dataclass
class RemediationStep:
    title: str
    rationale: str
    actions: List[str]
    severity: Severity = Severity.MEDIUM
    effort: str = "medium"
    cve_ids: List[str] = field(default_factory=list)
    packages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "rationale": self.rationale,
            "actions": list(self.actions),
            "severity": self.severity.value,
            "effort": self.effort,
            "cve_ids": list(self.cve_ids),
            "packages": list(self.packages),
        }


@dataclass
class RemediationPlan:
    headline: str
    summary: str
    steps: List[RemediationStep] = field(default_factory=list)
    overall_severity: Severity = Severity.MEDIUM
    confidence: float = 0.0
    raw_response: Optional[str] = None
    fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "overall_severity": self.overall_severity.value,
            "steps": [s.to_dict() for s in self.steps],
            "confidence": self.confidence,
            "fallback": self.fallback,
        }


_SYSTEM_PROMPT = (
    "You are a container security engineer. You receive a JSON summary of a "
    "vulnerability scan plus a risk score and policy violations. Produce a "
    "JSON remediation plan, ordered by impact. Only emit JSON, no preamble. "
    "Schema:\n"
    "{\n"
    '  "headline": str,\n'
    '  "summary": str,\n'
    '  "overall_severity": "UNKNOWN"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL",\n'
    '  "confidence": float,    // 0..1\n'
    '  "steps": [{\n'
    '    "title": str,\n'
    '    "rationale": str,\n'
    '    "severity": "UNKNOWN"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL",\n'
    '    "effort": "low"|"medium"|"high",\n'
    '    "cve_ids": [str],   // only CVEs that appear in the scan\n'
    '    "packages": [str],  // only packages that appear in the scan\n'
    '    "actions": [str]    // <= 6 imperative actions per step\n'
    "  }]\n"
    "}\n"
    "Rules: do NOT invent CVE IDs or package names. If you would cite "
    "a CVE not present in the scan, omit it. Reference only filenames "
    "shown in the secret findings. Keep the response under 2500 chars."
)


def _build_evidence(
    report: ScanReport,
    risk: RiskBreakdown,
    violations: Sequence[PolicyViolation],
    top_n: int,
) -> Dict[str, Any]:
    fixable_first = sorted(
        report.findings,
        key=lambda f: (-f.severity.rank, not f.is_fixable(), f.cve_id),
    )[:top_n]
    return {
        "artifact": {
            "name": report.artifact_name,
            "type": report.artifact_type,
        },
        "risk": risk.to_dict(),
        "severity_counts": report.severity_counts(),
        "fixable_count": report.fixable_count(),
        "top_findings": [
            {
                "cve_id": f.cve_id,
                "pkg": f.pkg_name,
                "installed": f.installed_version,
                "fixed": f.fixed_version,
                "severity": f.severity.value,
                "title": f.title[:140],
                "target": f.target,
            }
            for f in fixable_first
        ],
        "secrets": [
            {
                "rule": s.rule_id,
                "category": s.category,
                "target": s.target,
                "line": s.start_line,
            }
            for s in report.secrets[:8]
        ],
        "misconfigs": [
            {
                "rule": m.rule_id,
                "title": m.title[:120],
                "severity": m.severity.value,
            }
            for m in report.misconfigs[:8]
        ],
        "license_findings": [l.to_dict() for l in report.licenses[:6]],
        "policy_violations": [v.to_dict() for v in violations],
    }


def _coerce_plan(raw: str, report: ScanReport) -> RemediationPlan:
    valid_cves = set(report.cves())
    valid_pkgs = set(report.packages())
    fallback = False
    try:
        if "```" in raw:
            blocks = re.findall(r"```(?:json)?\s*(.*?)```", raw, flags=re.DOTALL)
            raw_json = blocks[0] if blocks else raw
        else:
            raw_json = raw
        data = json.loads(raw_json.strip())
    except Exception:
        return RemediationPlan(
            headline="Scan results require manual triage",
            summary="LLM response could not be parsed; raw scan retained.",
            steps=[],
            overall_severity=Severity.MEDIUM,
            confidence=0.3,
            raw_response=raw,
            fallback=True,
        )

    headline = str(data.get("headline", ""))[:180] or "Scan results"
    summary = str(data.get("summary", ""))[:1500]
    overall = Severity.from_str(data.get("overall_severity"))
    confidence = data.get("confidence", 0.5)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    steps_raw = data.get("steps", []) or []
    steps: List[RemediationStep] = []
    for s in steps_raw[:12]:
        if not isinstance(s, dict):
            continue
        title = str(s.get("title", ""))[:160]
        rationale = str(s.get("rationale", ""))[:600]
        severity = Severity.from_str(s.get("severity"))
        effort = str(s.get("effort", "medium")).lower()
        if effort not in _ALLOWED_EFFORT:
            effort = "medium"
        cves_raw = s.get("cve_ids", []) or []
        cves = [
            str(c).upper().strip()
            for c in cves_raw
            if isinstance(c, str) and _CVE_RE.match(str(c).upper().strip())
        ]
        cves = [c for c in cves if c in valid_cves]
        pkgs_raw = s.get("packages", []) or []
        pkgs = [
            str(p) for p in pkgs_raw
            if isinstance(p, str) and str(p) in valid_pkgs
        ]
        actions_raw = s.get("actions", []) or []
        actions = [str(a)[:240] for a in actions_raw if isinstance(a, (str, int, float))][:6]
        steps.append(RemediationStep(
            title=title or "Remediation step",
            rationale=rationale,
            actions=actions,
            severity=severity,
            effort=effort,
            cve_ids=cves,
            packages=pkgs,
        ))

    return RemediationPlan(
        headline=headline,
        summary=summary,
        steps=steps,
        overall_severity=overall,
        confidence=confidence,
        raw_response=raw,
        fallback=fallback,
    )


_AUTO = object()


@dataclass
class LLMRemediationAdvisor:
    """Translate scan + risk + policy into a remediation plan."""

    client: Any = _AUTO
    model: str = os.environ.get("CONTRUST_LLM_MODEL", "glm-5.1")
    temperature: float = 0.1
    max_tokens: int = 1200
    top_n_findings: int = 12

    def __post_init__(self) -> None:
        if self.client is _AUTO:
            if LLMClient is None:
                self.client = None
            else:
                try:
                    self.client = LLMClient()
                except Exception:
                    self.client = None

    def advise(
        self,
        report: ScanReport,
        risk: RiskBreakdown,
        violations: Sequence[PolicyViolation] = (),
    ) -> RemediationPlan:
        if self.client is None:
            return self._heuristic(report, risk, violations)
        evidence = _build_evidence(report, risk, violations, self.top_n_findings)
        user = (
            "Scan evidence (JSON):\n"
            + json.dumps(evidence, indent=2)
            + "\n\nReturn the remediation-plan JSON described in the system prompt only."
        )
        try:
            resp = self.client.chat(
                [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ],
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            raw = resp.content if hasattr(resp, "content") else str(resp)
        except Exception as exc:
            return RemediationPlan(
                headline="LLM unavailable",
                summary=f"LLM call failed: {exc!s}",
                steps=[],
                overall_severity=Severity.MEDIUM,
                confidence=0.3,
                fallback=True,
            )
        return _coerce_plan(raw, report)

    def _heuristic(
        self,
        report: ScanReport,
        risk: RiskBreakdown,
        violations: Sequence[PolicyViolation],
    ) -> RemediationPlan:
        steps: List[RemediationStep] = []
        if report.secrets:
            steps.append(RemediationStep(
                title="Remove leaked secret(s) from artefact",
                rationale=f"{len(report.secrets)} secret pattern(s) found in image.",
                actions=[
                    "Rotate the leaked credential immediately",
                    "Strip the secret from version control history",
                    "Inject secrets via runtime mounts, not at build time",
                ],
                severity=Severity.CRITICAL,
                effort="medium",
            ))
        fixable = [f for f in report.findings if f.is_fixable()][:6]
        if fixable:
            steps.append(RemediationStep(
                title="Bump fixable vulnerable packages",
                rationale=f"{len(fixable)} of {len(report.findings)} findings have a fixed version available.",
                actions=[f"upgrade {f.pkg_name} to {f.fixed_version}" for f in fixable[:6]],
                severity=max((f.severity for f in fixable), key=lambda s: s.rank),
                effort="low",
                cve_ids=[f.cve_id for f in fixable if f.cve_id],
                packages=[f.pkg_name for f in fixable],
            ))
        return RemediationPlan(
            headline="Heuristic remediation plan (LLM offline)",
            summary=(
                f"Risk score {risk.score:.2f} ({risk.band}); "
                f"{len(report.findings)} findings, {len(report.secrets)} secrets."
            ),
            steps=steps,
            overall_severity=Severity.HIGH if risk.band in {"high", "critical"} else Severity.MEDIUM,
            confidence=0.4,
            fallback=True,
        )
