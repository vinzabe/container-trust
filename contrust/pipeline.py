"""End-to-end orchestration: scan -> risk -> policy -> advise."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .advisor import LLMRemediationAdvisor, RemediationPlan
from .findings import ScanReport
from .parser import parse_trivy_file
from .policy import Policy, PolicyDecision, PolicyViolation, evaluate_policy
from .risk import RiskBreakdown, RiskModel
from .scanner import TargetKind, TrivyScanner


@dataclass
class PipelineResult:
    report: ScanReport
    risk: RiskBreakdown
    decision: PolicyDecision
    violations: List[PolicyViolation] = field(default_factory=list)
    plan: Optional[RemediationPlan] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report": self.report.to_dict(),
            "risk": self.risk.to_dict(),
            "decision": self.decision.value,
            "violations": [v.to_dict() for v in self.violations],
            "plan": self.plan.to_dict() if self.plan else None,
        }


@dataclass
class TrustPipeline:
    scanner: Optional[TrivyScanner] = None
    risk_model: RiskModel = field(default_factory=RiskModel)
    policy: Policy = field(default_factory=Policy)
    advisor: Optional[LLMRemediationAdvisor] = None
    enable_llm: bool = True

    def run_image(self, image: str) -> PipelineResult:
        if self.scanner is None:
            raise RuntimeError("scanner not configured for live mode")
        report = self.scanner.scan(TargetKind.IMAGE, image)
        return self._post(report)

    def run_fs(self, path: str) -> PipelineResult:
        if self.scanner is None:
            raise RuntimeError("scanner not configured for live mode")
        report = self.scanner.scan(TargetKind.FS, path)
        return self._post(report)

    def run_from_json(self, path: str) -> PipelineResult:
        report = parse_trivy_file(path)
        return self._post(report)

    def run_from_report(self, report: ScanReport) -> PipelineResult:
        return self._post(report)

    def _post(self, report: ScanReport) -> PipelineResult:
        risk = self.risk_model.score(report)
        ev = evaluate_policy(report, self.policy, score=risk.score)
        plan: Optional[RemediationPlan] = None
        if self.enable_llm and self.advisor is not None:
            plan = self.advisor.advise(report, risk, ev.violations)
        return PipelineResult(
            report=report,
            risk=risk,
            decision=ev.decision,
            violations=ev.violations,
            plan=plan,
        )
