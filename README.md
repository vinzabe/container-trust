# container-trust

A **container & artefact trust scanner** that wraps `trivy`, normalises
its output, scores risk deterministically, applies operator policy
gates, and asks an LLM for a prioritised remediation plan -- with
hallucination guards that drop any CVE or package the LLM invents.

```
trivy {image|fs|sbom|rootfs}
   -> ScanReport          normalised dataclasses (findings, secrets,
                          misconfigs, licenses)
   -> RiskModel           deterministic 0..100 score with 5-component
                          breakdown
   -> Policy              PASS / WARN / FAIL gate with named violations
   -> LLMRemediationAdvisor prioritised plan, every CVE/package cross-
                            checked against the actual scan
```

## Why a wrapper?

Raw `trivy` output is operationally noisy:

* schema changes between minor versions
* hundreds of LOW findings drown out the one CRITICAL that matters
* CVSS scores live in nested `CVSS.{nvd,ghsa,redhat}.V3Score`
* `Secrets`, `Misconfigurations` and `Licenses` are siblings of
  `Vulnerabilities` and are easy to miss

`container-trust` projects all of that into stable, JSON-serialisable
dataclasses, then layers a deterministic `RiskModel` and a configurable
`Policy` on top so operators can encode their trust decisions in CI.

## Hallucination guards (the part that matters)

The LLM advisor is **only** asked to prioritise findings that already
came back in the scan.  Every claim it makes is validated:

* `cve_ids`   -- must match `CVE-\d{4}-\d{4,}` *and* appear in `report.cves()`
* `packages`  -- must appear in `report.packages()`
* `severity`  -- clamped to `UNKNOWN..CRITICAL`
* `effort`    -- clamped to `low|medium|high`
* `confidence` -- clamped to `[0, 1]`
* `steps`     -- capped at 12, `actions` capped at 6 per step

Anything that fails validation is silently dropped.  On garbled JSON
the advisor falls back to a deterministic heuristic plan and sets
`fallback=True`.

## Quick start

```bash
pip install -r requirements.txt

# scan a container image (live trivy, requires DB)
python -m contrust.cli image docker.io/library/nginx:1.25 --llm

# scan a filesystem path
python -m contrust.cli fs ./my-repo --llm

# replay a saved trivy JSON file (offline-friendly)
python -m contrust.cli replay --json fixtures/synthetic_high_risk.json --llm
```

## Library use

```python
from contrust import (
    TrivyScanner, RiskModel, Policy, LLMRemediationAdvisor, TrustPipeline,
)

pipeline = TrustPipeline(
    scanner=TrivyScanner(),
    risk_model=RiskModel(),
    policy=Policy(max_critical=0, deny_secrets=True),
    advisor=LLMRemediationAdvisor(),
)
result = pipeline.run_image("docker.io/library/nginx:1.25")
print(result.decision, result.risk.band, len(result.violations))
for step in result.plan.steps:
    print(step.severity.value, step.title, step.cve_ids)
```

## Sample LLM live output

On `fixtures/synthetic_high_risk.json` (Log4Shell + leaked AWS key
+ AGPL-3.0 dependency + missing-USER Dockerfile rule):

```
headline:   Critical Log4Shell RCE and AWS key leak in synthetic.example/app:1.0
severity:   CRITICAL
confidence: 0.95
steps:      6
cves cited: 4
```

All 4 cited CVEs are present in the input scan; none were invented.

## Layout

```
contrust/
  findings.py    Severity, Finding, SecretFinding, LicenseFinding,
                 MisconfigFinding, ScanReport
  parser.py      trivy JSON -> normalised ScanReport
  scanner.py     subprocess wrapper + TrivyConfig + TargetKind
  risk.py        deterministic RiskModel + RiskBreakdown
  policy.py      Policy, PolicyDecision, evaluate_policy
  advisor.py     LLMRemediationAdvisor + RemediationPlan (validated)
  pipeline.py    TrustPipeline + PipelineResult
  cli.py         contrust {image, fs, replay}
fixtures/
  synthetic_high_risk.json  hand-crafted: log4shell + leaked AWS key
  vulnerable_app.json       real trivy output: requests/django/flask CVEs
  secrets_leak.json         real trivy output: leaked GitHub PAT
tests/
  test_contrust.py          48 unit + 1 LLM_LIVE smoke
```

## Tests

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/ -v
```

48 unit tests cover parser robustness, risk-model edge cases, policy
gates, advisor hallucination guards, and pipeline end-to-end.
1 LLM_LIVE smoke validates that every CVE cited in the LLM plan is
present in the input scan.

## License

MIT
