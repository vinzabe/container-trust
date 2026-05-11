"""contrust -- Container & artifact image trust scanner.

A wrapper around `trivy` that:

  * runs `trivy` in image / filesystem / SBOM mode,
  * normalises its JSON output into stable dataclasses,
  * scores the artefact with a deterministic risk model,
  * applies operator policy gates (max severity, banned packages,
    secret-on-disk, license deny-list),
  * asks an LLM for a prioritised remediation plan,
  * validates every CVE / package the LLM mentions against the
    actual scan to suppress hallucination.

The package never elevates privileges; trivy is invoked as a subprocess
and we always pass `--exit-code 0` so the scan is a *report*, not a
gate.  Gating is the operator's policy decision, applied separately by
``contrust.policy``.
"""

from .findings import (
    Finding,
    Severity,
    SecretFinding,
    LicenseFinding,
    MisconfigFinding,
    ScanReport,
)
from .parser import parse_trivy_json, parse_trivy_file
from .scanner import (
    TrivyScanner,
    TrivyConfig,
    TrivyError,
)
from .risk import RiskModel, RiskBreakdown
from .policy import (
    Policy,
    PolicyDecision,
    PolicyViolation,
    evaluate_policy,
)
from .advisor import (
    LLMRemediationAdvisor,
    RemediationPlan,
    RemediationStep,
)
from .pipeline import TrustPipeline, PipelineResult

__all__ = [
    "Finding",
    "Severity",
    "SecretFinding",
    "LicenseFinding",
    "MisconfigFinding",
    "ScanReport",
    "parse_trivy_json",
    "parse_trivy_file",
    "TrivyScanner",
    "TrivyConfig",
    "TrivyError",
    "RiskModel",
    "RiskBreakdown",
    "Policy",
    "PolicyDecision",
    "PolicyViolation",
    "evaluate_policy",
    "LLMRemediationAdvisor",
    "RemediationPlan",
    "RemediationStep",
    "TrustPipeline",
    "PipelineResult",
]
