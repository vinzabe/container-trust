"""contrust test-suite.

Layout:
  - findings           -- dataclass behaviour + severity rank
  - parser             -- trivy schema -> normalised report
  - scanner            -- subprocess wrapper construction
  - risk               -- deterministic scoring
  - policy             -- gate evaluation
  - advisor            -- LLM coercion + hallucination guards
  - pipeline           -- end-to-end with FakeLLM and real fixtures
  - LLM_LIVE smoke     -- full pipeline with real LLM
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from contrust import (
    Finding,
    LicenseFinding,
    LLMRemediationAdvisor,
    MisconfigFinding,
    Policy,
    PolicyDecision,
    RiskModel,
    ScanReport,
    SecretFinding,
    Severity,
    TrivyConfig,
    TrivyError,
    TrivyScanner,
    TrustPipeline,
    evaluate_policy,
    parse_trivy_file,
    parse_trivy_json,
)
from contrust.advisor import _coerce_plan
from contrust.scanner import TargetKind

FIXTURE_DIR = Path(_HERE).parent / "fixtures"


# ---- findings ------------------------------------------------------------


def test_severity_rank_orders_correctly():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.LOW.rank > Severity.UNKNOWN.rank


def test_severity_from_str_handles_garbage():
    assert Severity.from_str(None) == Severity.UNKNOWN
    assert Severity.from_str("critical") == Severity.CRITICAL
    assert Severity.from_str("Whatever") == Severity.UNKNOWN


def test_finding_is_fixable_when_versions_differ():
    f = Finding(
        cve_id="CVE-1", pkg_name="x", installed_version="1.0",
        fixed_version="1.1", severity=Severity.HIGH, title="t", target="t",
    )
    assert f.is_fixable() is True


def test_finding_not_fixable_when_no_fix_or_same_version():
    f = Finding(cve_id="CVE-1", pkg_name="x", installed_version="1.0",
                fixed_version=None, severity=Severity.HIGH, title="t", target="t")
    assert f.is_fixable() is False
    f2 = Finding(cve_id="CVE-1", pkg_name="x", installed_version="1.0",
                 fixed_version="1.0", severity=Severity.HIGH, title="t", target="t")
    assert f2.is_fixable() is False


def test_scan_report_severity_counts_aggregates():
    r = ScanReport(artifact_name="x", artifact_type="image", schema_version=2)
    r.findings.append(Finding("CVE-A", "p1", "1", "2", Severity.HIGH, "t", "f"))
    r.findings.append(Finding("CVE-B", "p1", "1", None, Severity.HIGH, "t", "f"))
    r.findings.append(Finding("CVE-C", "p2", "1", "2", Severity.LOW, "t", "f"))
    counts = r.severity_counts()
    assert counts["HIGH"] == 2
    assert counts["LOW"] == 1
    assert counts["CRITICAL"] == 0


def test_scan_report_packages_and_cves_dedupe():
    r = ScanReport(artifact_name="x", artifact_type="image", schema_version=2)
    r.findings.append(Finding("CVE-A", "p", "1", "2", Severity.HIGH, "t", "f"))
    r.findings.append(Finding("CVE-A", "p", "1", "2", Severity.HIGH, "t", "f"))
    assert r.packages() == ["p"]
    assert r.cves() == ["CVE-A"]


# ---- parser --------------------------------------------------------------


def test_parser_rejects_non_object_root():
    with pytest.raises(ValueError):
        parse_trivy_json([])  # type: ignore[arg-type]


def test_parser_handles_empty_results():
    rep = parse_trivy_json({"SchemaVersion": 2, "Results": []})
    assert rep.findings == []
    assert rep.severity_counts()["HIGH"] == 0


def test_parser_loads_synthetic_high_risk_fixture():
    rep = parse_trivy_file(str(FIXTURE_DIR / "synthetic_high_risk.json"))
    assert rep.artifact_name == "synthetic.example/app:1.0"
    assert any(f.cve_id == "CVE-2021-44228" for f in rep.findings)
    assert any(f.severity == Severity.CRITICAL for f in rep.findings)
    assert len(rep.secrets) == 1
    assert rep.secrets[0].rule_id == "aws-access-key-id"
    assert any(m.rule_id == "DS002" for m in rep.misconfigs)
    assert any(l.license == "AGPL-3.0" for l in rep.licenses)


def test_parser_extracts_cvss_score_when_available():
    rep = parse_trivy_file(str(FIXTURE_DIR / "synthetic_high_risk.json"))
    log4shell = next(f for f in rep.findings if f.cve_id == "CVE-2021-44228")
    assert log4shell.cvss_score == 10.0


def test_parser_loads_real_trivy_output_with_vulns():
    rep = parse_trivy_file(str(FIXTURE_DIR / "vulnerable_app.json"))
    assert len(rep.findings) > 0
    # we put requests/django/flask in -- at least one CVE should mention them
    pkgs = {f.pkg_name for f in rep.findings}
    assert pkgs.intersection({"requests", "django", "Django", "flask", "Flask"})


def test_parser_loads_real_trivy_output_with_secrets():
    rep = parse_trivy_file(str(FIXTURE_DIR / "secrets_leak.json"))
    assert len(rep.secrets) >= 1
    assert any("github" in s.rule_id.lower() for s in rep.secrets)


def test_parser_truncates_secret_match_strings():
    blob = {
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [{
            "Target": "f",
            "Secrets": [{
                "RuleID": "x", "Category": "y", "Severity": "HIGH",
                "Title": "t", "StartLine": 1, "EndLine": 1,
                "Match": "x" * 1000,
            }],
        }],
    }
    rep = parse_trivy_json(blob)
    assert len(rep.secrets[0].match) <= 240


def test_parser_skips_non_dict_result_entries():
    blob = {
        "SchemaVersion": 2,
        "Results": ["bogus", {"Target": "ok", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-x", "PkgName": "p",
            "InstalledVersion": "1", "Severity": "LOW",
        }]}],
    }
    rep = parse_trivy_json(blob)
    assert len(rep.findings) == 1


# ---- scanner -------------------------------------------------------------


def test_scanner_init_rejects_missing_binary():
    with pytest.raises(TrivyError):
        TrivyScanner(TrivyConfig(binary="definitely_not_a_real_binary_42"))


def test_scanner_build_argv_contains_required_flags():
    s = TrivyScanner()
    argv = s._build_argv(TargetKind.IMAGE, "alpine:3.18")
    assert "image" in argv
    assert "--format" in argv and "json" in argv
    assert "--exit-code" in argv
    assert argv[-1] == "alpine:3.18"


def test_scanner_scan_rejects_empty_target():
    s = TrivyScanner()
    with pytest.raises(TrivyError):
        s.scan(TargetKind.IMAGE, "")


def test_scanner_offline_flag_propagates():
    s = TrivyScanner(TrivyConfig(offline=True, skip_db_update=True))
    argv = s._build_argv(TargetKind.FS, "/tmp")
    assert "--offline-scan" in argv
    assert "--skip-db-update" in argv


# ---- risk ----------------------------------------------------------------


def _make_report_with(crit=0, high=0, med=0, low=0, secrets=0, misconfigs=0, licenses=0):
    r = ScanReport(artifact_name="x", artifact_type="image", schema_version=2)
    for sev, n in (("CRITICAL", crit), ("HIGH", high), ("MEDIUM", med), ("LOW", low)):
        for i in range(n):
            r.findings.append(Finding(
                cve_id=f"CVE-{sev}-{i}", pkg_name=f"p{i}", installed_version="1",
                fixed_version="2", severity=Severity(sev), title="t", target="t",
            ))
    for i in range(secrets):
        r.secrets.append(SecretFinding(
            rule_id="r", category="c", severity=Severity.HIGH,
            title="t", target="x", start_line=1, end_line=1, match="m",
        ))
    for i in range(misconfigs):
        r.misconfigs.append(MisconfigFinding(
            rule_id="x", severity=Severity.HIGH, title="t", target="x", message="m",
        ))
    for i in range(licenses):
        r.licenses.append(LicenseFinding(
            pkg_name="p", license="AGPL-3.0", severity=Severity.HIGH, target="t",
        ))
    return r


def test_risk_clean_report_scores_minimal():
    r = _make_report_with()
    rb = RiskModel().score(r)
    assert rb.score == 0.0
    assert rb.band == "minimal"


def test_risk_single_secret_contributes_secret_subscore():
    r = _make_report_with(secrets=1)
    rb = RiskModel().score(r)
    assert rb.secret_subscore == 25.0
    assert rb.band in {"low", "medium", "high", "critical"}


def test_risk_two_secrets_push_to_medium_band_or_higher():
    r = _make_report_with(secrets=2)
    rb = RiskModel().score(r)
    assert rb.band in {"medium", "high", "critical"}


def test_risk_single_critical_pushes_to_high_band():
    r = _make_report_with(crit=1)
    rb = RiskModel().score(r)
    assert rb.band in {"low", "medium", "high"}
    assert rb.severity_subscore >= 18.0


def test_risk_caps_severity_subscore():
    r = _make_report_with(crit=20)  # 20 * 18 = 360 -> capped
    rb = RiskModel().score(r)
    assert rb.severity_subscore == RiskModel().sev_cap


def test_risk_score_clamps_to_100():
    r = _make_report_with(crit=20, high=20, med=20, secrets=20, misconfigs=20, licenses=20)
    rb = RiskModel().score(r)
    assert rb.score <= 100.0


def test_risk_breakdown_components_count_correctly():
    r = _make_report_with(crit=2, high=3, secrets=1)
    rb = RiskModel().score(r)
    assert rb.components["n_critical"] == 2
    assert rb.components["n_high"] == 3
    assert rb.components["n_secrets"] == 1


# ---- policy --------------------------------------------------------------


def test_policy_pass_on_clean_report():
    r = _make_report_with()
    res = evaluate_policy(r, Policy(), score=0.0)
    assert res.decision == PolicyDecision.PASS
    assert res.violations == []


def test_policy_fails_on_critical_over_limit():
    r = _make_report_with(crit=1)
    res = evaluate_policy(r, Policy(max_critical=0), score=20.0)
    assert res.decision == PolicyDecision.FAIL
    assert any(v.code == "CRITICAL_OVER_LIMIT" for v in res.violations)


def test_policy_fails_on_high_over_limit():
    r = _make_report_with(high=10)
    res = evaluate_policy(r, Policy(max_critical=0, max_high=2), score=20.0)
    assert res.decision == PolicyDecision.FAIL
    assert any(v.code == "HIGH_OVER_LIMIT" for v in res.violations)


def test_policy_unfixed_high_severity_when_disallowed():
    r = ScanReport(artifact_name="x", artifact_type="image", schema_version=2)
    r.findings.append(Finding("CVE-X", "p", "1", None, Severity.CRITICAL, "t", "f"))
    res = evaluate_policy(r, Policy(max_critical=99, allow_unfixed=False), score=20.0)
    assert any(v.code == "UNFIXED_HIGH_SEVERITY" for v in res.violations)


def test_policy_unfixed_allowed_when_set():
    r = ScanReport(artifact_name="x", artifact_type="image", schema_version=2)
    r.findings.append(Finding("CVE-X", "p", "1", None, Severity.HIGH, "t", "f"))
    res = evaluate_policy(r, Policy(max_critical=99, max_high=99, allow_unfixed=True), score=20.0)
    assert all(v.code != "UNFIXED_HIGH_SEVERITY" for v in res.violations)


def test_policy_banned_packages_substring_match():
    r = ScanReport(artifact_name="x", artifact_type="image", schema_version=2)
    r.findings.append(Finding("CVE-X", "openssl-libs", "1", "2", Severity.LOW, "t", "f"))
    res = evaluate_policy(r, Policy(banned_packages=["openssl"]), score=10.0)
    assert any(v.code == "BANNED_PACKAGE" for v in res.violations)


def test_policy_banned_licenses_exact_match_only():
    r = ScanReport(artifact_name="x", artifact_type="image", schema_version=2)
    r.licenses.append(LicenseFinding("p", "AGPL-3.0", Severity.HIGH, "t"))
    res = evaluate_policy(r, Policy(banned_licenses=["AGPL-3.0"]), score=10.0)
    assert any(v.code == "BANNED_LICENSE" for v in res.violations)


def test_policy_secret_leak_is_critical():
    r = _make_report_with(secrets=1)
    res = evaluate_policy(r, Policy(deny_secrets=True), score=25.0)
    assert any(v.code == "SECRET_LEAK" for v in res.violations)
    assert res.decision == PolicyDecision.FAIL


def test_policy_score_warn_threshold_yields_warn():
    r = _make_report_with(med=2)
    # no violations, only score-based
    res = evaluate_policy(r, Policy(score_warn=2.0, score_fail=99.0), score=5.0)
    assert res.decision == PolicyDecision.WARN


def test_policy_score_fail_threshold_yields_fail():
    r = _make_report_with(med=2)
    res = evaluate_policy(r, Policy(score_warn=10.0, score_fail=20.0), score=80.0)
    assert res.decision == PolicyDecision.FAIL


# ---- advisor coerce ------------------------------------------------------


def _make_synth_report():
    return parse_trivy_file(str(FIXTURE_DIR / "synthetic_high_risk.json"))


def test_coerce_plan_drops_invented_cves():
    rep = _make_synth_report()
    valid = "CVE-2021-44228"
    raw = json.dumps({
        "headline": "x", "summary": "s", "overall_severity": "CRITICAL", "confidence": 0.9,
        "steps": [{
            "title": "step", "rationale": "r", "severity": "HIGH", "effort": "low",
            "cve_ids": [valid, "CVE-9999-99999"],  # second is hallucinated
            "packages": [], "actions": ["x"],
        }],
    })
    plan = _coerce_plan(raw, rep)
    assert plan.steps[0].cve_ids == [valid]


def test_coerce_plan_drops_invented_packages():
    rep = _make_synth_report()
    raw = json.dumps({
        "headline": "x", "summary": "s", "overall_severity": "HIGH", "confidence": 0.7,
        "steps": [{
            "title": "step", "rationale": "r", "severity": "HIGH", "effort": "low",
            "cve_ids": [],
            "packages": ["log4j-core", "made-up-pkg"],
            "actions": ["x"],
        }],
    })
    plan = _coerce_plan(raw, rep)
    assert "made-up-pkg" not in plan.steps[0].packages
    assert "log4j-core" in plan.steps[0].packages


def test_coerce_plan_clamps_confidence():
    rep = _make_synth_report()
    raw = json.dumps({
        "headline": "x", "summary": "s", "overall_severity": "HIGH",
        "confidence": 99.0, "steps": [],
    })
    plan = _coerce_plan(raw, rep)
    assert plan.confidence == 1.0


def test_coerce_plan_clamps_effort_to_known():
    rep = _make_synth_report()
    raw = json.dumps({
        "headline": "x", "summary": "s", "overall_severity": "MEDIUM", "confidence": 0.5,
        "steps": [{"title": "t", "rationale": "r", "severity": "HIGH",
                   "effort": "godlike", "cve_ids": [], "packages": [], "actions": []}],
    })
    plan = _coerce_plan(raw, rep)
    assert plan.steps[0].effort == "medium"


def test_coerce_plan_garbled_response_returns_fallback():
    rep = _make_synth_report()
    plan = _coerce_plan("not json at all", rep)
    assert plan.fallback is True


def test_coerce_plan_handles_codefence():
    rep = _make_synth_report()
    payload = {
        "headline": "x", "summary": "s", "overall_severity": "HIGH", "confidence": 0.5,
        "steps": [],
    }
    raw = "Sure thing:\n```json\n" + json.dumps(payload) + "\n```"
    plan = _coerce_plan(raw, rep)
    assert plan.fallback is False


def test_coerce_plan_caps_steps_to_12():
    rep = _make_synth_report()
    steps = [{"title": f"s{i}", "rationale": "r", "severity": "LOW",
              "effort": "low", "cve_ids": [], "packages": [], "actions": []}
             for i in range(50)]
    raw = json.dumps({"headline": "x", "summary": "s", "overall_severity": "LOW",
                      "confidence": 0.5, "steps": steps})
    plan = _coerce_plan(raw, rep)
    assert len(plan.steps) == 12


def test_advisor_with_no_client_returns_heuristic_plan():
    rep = _make_synth_report()
    risk = RiskModel().score(rep)
    advisor = LLMRemediationAdvisor(client=None)
    plan = advisor.advise(rep, risk, [])
    assert plan.fallback is True
    # heuristic should mention secrets and fixable upgrades
    titles = " ".join(s.title.lower() for s in plan.steps)
    assert "secret" in titles or "bump" in titles or "upgrade" in titles


# ---- pipeline ------------------------------------------------------------


class _FakeLLM:
    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    def chat(self, *args, **kwargs):
        self.calls += 1
        content = self._payload if isinstance(self._payload, str) else json.dumps(self._payload)
        return types.SimpleNamespace(content=content)


def test_pipeline_run_from_report_synthetic_critical():
    rep = _make_synth_report()
    fake = _FakeLLM({
        "headline": "Log4Shell + leaked AWS creds + AGPL package",
        "summary": "Critical RCE plus a leaked secret put this image in a fail state.",
        "overall_severity": "CRITICAL", "confidence": 0.95,
        "steps": [{
            "title": "Bump log4j-core to 2.17.1",
            "rationale": "Pinned at 2.14.1 which is vulnerable to JNDI lookup RCE.",
            "severity": "CRITICAL", "effort": "low",
            "cve_ids": ["CVE-2021-44228"],
            "packages": ["log4j-core"],
            "actions": ["upgrade pin to 2.17.1", "rebuild image"],
        }],
    })
    advisor = LLMRemediationAdvisor(client=fake)
    pipeline = TrustPipeline(
        scanner=None, advisor=advisor, enable_llm=True,
        policy=Policy(max_critical=0, deny_secrets=True),
    )
    result = pipeline.run_from_report(rep)
    assert result.decision == PolicyDecision.FAIL
    assert result.risk.band in {"high", "critical"}
    assert any(v.code == "SECRET_LEAK" for v in result.violations)
    assert any(v.code == "CRITICAL_OVER_LIMIT" for v in result.violations)
    assert result.plan is not None
    assert result.plan.steps[0].cve_ids == ["CVE-2021-44228"]


def test_pipeline_run_from_report_clean_passes():
    rep = ScanReport(artifact_name="clean", artifact_type="image", schema_version=2)
    pipeline = TrustPipeline(scanner=None, advisor=None, enable_llm=False)
    result = pipeline.run_from_report(rep)
    assert result.decision == PolicyDecision.PASS
    assert result.risk.band == "minimal"
    assert result.plan is None


def test_pipeline_with_real_vuln_fixture_yields_findings():
    pipeline = TrustPipeline(scanner=None, advisor=None, enable_llm=False)
    result = pipeline.run_from_json(str(FIXTURE_DIR / "vulnerable_app.json"))
    assert len(result.report.findings) > 0
    assert result.risk.score > 0


def test_pipeline_with_real_secret_fixture_fails_policy():
    pipeline = TrustPipeline(
        scanner=None, advisor=None, enable_llm=False,
        policy=Policy(deny_secrets=True),
    )
    result = pipeline.run_from_json(str(FIXTURE_DIR / "secrets_leak.json"))
    assert result.decision == PolicyDecision.FAIL
    assert any(v.code == "SECRET_LEAK" for v in result.violations)


def test_pipeline_to_dict_is_json_serialisable():
    rep = _make_synth_report()
    pipeline = TrustPipeline(scanner=None, advisor=None, enable_llm=False)
    result = pipeline.run_from_report(rep)
    blob = json.dumps(result.to_dict(), default=str)
    assert "decision" in blob and "risk" in blob


# ---- LLM live ------------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("LLM_LIVE") != "1",
    reason="set LLM_LIVE=1 to run live LLM smoke",
)
def test_llm_live_remediation_plan_grounded_in_fixture():
    rep = _make_synth_report()
    advisor = LLMRemediationAdvisor()
    pipeline = TrustPipeline(
        scanner=None, advisor=advisor, enable_llm=True,
        policy=Policy(max_critical=0, deny_secrets=True),
    )
    result = pipeline.run_from_report(rep)
    assert result.plan is not None
    print(f"\nlive remediation plan:")
    print(f"  headline:   {result.plan.headline}")
    print(f"  severity:   {result.plan.overall_severity.value}")
    print(f"  confidence: {result.plan.confidence}")
    print(f"  steps:      {len(result.plan.steps)}")
    print(f"  cves cited: {sum(len(s.cve_ids) for s in result.plan.steps)}")
    # decision should be FAIL given critical + secret
    assert result.decision == PolicyDecision.FAIL
    # all CVEs the LLM cited must come from the actual scan
    actual_cves = set(rep.cves())
    for step in result.plan.steps:
        for cve in step.cve_ids:
            assert cve in actual_cves, f"hallucinated cve {cve}"
    # plan must mention log4shell or critical somewhere
    blob = (result.plan.headline + " " + result.plan.summary).lower()
    assert any(t in blob for t in ("log4j", "log4shell", "44228", "critical", "secret"))
    assert 0.0 <= result.plan.confidence <= 1.0
