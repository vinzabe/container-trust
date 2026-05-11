"""Trivy JSON parser.

We accept the full ``trivy`` v0.50+ schema (`SchemaVersion: 2`) and
silently ignore unknown sub-fields so we forward-compat through minor
upgrades.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .findings import (
    Finding,
    LicenseFinding,
    MisconfigFinding,
    ScanReport,
    SecretFinding,
    Severity,
)


def _coerce_finding(raw: Dict[str, Any], target: str) -> Finding:
    cvss_score = None
    cvss = raw.get("CVSS") or {}
    if isinstance(cvss, dict):
        # prefer NVD/v3, fallback to first available
        for src in ("nvd", "ghsa", "redhat"):
            entry = cvss.get(src)
            if isinstance(entry, dict):
                v = entry.get("V3Score") or entry.get("V2Score")
                if isinstance(v, (int, float)):
                    cvss_score = float(v)
                    break
        if cvss_score is None:
            for entry in cvss.values():
                if isinstance(entry, dict):
                    v = entry.get("V3Score") or entry.get("V2Score")
                    if isinstance(v, (int, float)):
                        cvss_score = float(v)
                        break
    return Finding(
        cve_id=str(raw.get("VulnerabilityID", "") or ""),
        pkg_name=str(raw.get("PkgName", "") or ""),
        installed_version=str(raw.get("InstalledVersion", "") or ""),
        fixed_version=raw.get("FixedVersion") or None,
        severity=Severity.from_str(raw.get("Severity")),
        title=str(raw.get("Title", "") or ""),
        target=target,
        primary_url=raw.get("PrimaryURL") or None,
        description=raw.get("Description"),
        cvss_score=cvss_score,
        status=raw.get("Status"),
    )


def _coerce_secret(raw: Dict[str, Any], target: str) -> SecretFinding:
    return SecretFinding(
        rule_id=str(raw.get("RuleID", "")),
        category=str(raw.get("Category", "")),
        severity=Severity.from_str(raw.get("Severity")),
        title=str(raw.get("Title", "")),
        target=target,
        start_line=int(raw.get("StartLine", 0) or 0),
        end_line=int(raw.get("EndLine", 0) or 0),
        match=str(raw.get("Match", ""))[:240],
    )


def _coerce_license(raw: Dict[str, Any], target: str) -> LicenseFinding:
    return LicenseFinding(
        pkg_name=str(raw.get("PkgName", "")),
        license=str(raw.get("Name", "")),
        severity=Severity.from_str(raw.get("Severity")),
        target=target,
        category=str(raw.get("Category", "package-license") or "package-license"),
    )


def _coerce_misconfig(raw: Dict[str, Any], target: str) -> MisconfigFinding:
    return MisconfigFinding(
        rule_id=str(raw.get("ID", "")),
        severity=Severity.from_str(raw.get("Severity")),
        title=str(raw.get("Title", "")),
        target=target,
        message=str(raw.get("Message", ""))[:500],
    )


def parse_trivy_json(blob: Dict[str, Any]) -> ScanReport:
    """Project a parsed trivy JSON document into a ``ScanReport``."""

    if not isinstance(blob, dict):
        raise ValueError("trivy JSON root must be an object")
    schema = int(blob.get("SchemaVersion", 0) or 0)
    artefact = str(blob.get("ArtifactName", "<unknown>") or "<unknown>")
    art_type = str(blob.get("ArtifactType", "unknown") or "unknown")
    findings: List[Finding] = []
    secrets: List[SecretFinding] = []
    licenses: List[LicenseFinding] = []
    misconfigs: List[MisconfigFinding] = []

    for result in blob.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", "<unknown>") or "<unknown>")
        for v in result.get("Vulnerabilities") or []:
            if isinstance(v, dict):
                findings.append(_coerce_finding(v, target))
        for s in result.get("Secrets") or []:
            if isinstance(s, dict):
                secrets.append(_coerce_secret(s, target))
        for l in result.get("Licenses") or []:
            if isinstance(l, dict):
                licenses.append(_coerce_license(l, target))
        for m in result.get("Misconfigurations") or []:
            if isinstance(m, dict):
                misconfigs.append(_coerce_misconfig(m, target))

    return ScanReport(
        artifact_name=artefact,
        artifact_type=art_type,
        schema_version=schema,
        findings=findings,
        secrets=secrets,
        licenses=licenses,
        misconfigs=misconfigs,
        raw=blob,
    )


def parse_trivy_file(path: str) -> ScanReport:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_trivy_json(json.load(fh))
