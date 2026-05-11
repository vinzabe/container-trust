# Security Policy

## Threat model

`container-trust` is a defensive build/CI tool: it inspects container
images, filesystems, and SBOMs for known vulnerabilities, leaked
secrets, misconfigurations, and license issues.  Two distinct risk
surfaces:

1. **Untrusted scan target.** The image / filesystem under scan may be
   adversarial.  We rely on `trivy` itself to be hardened against
   crafted artefacts; we never `eval` or execute anything we read from
   a target.
2. **LLM as advisor.** The LLM is asked to prioritise the scan; it
   must not be permitted to invent CVEs, recommend bogus package
   upgrades, or quote private operator data.

## In-package controls

### Scanner

* `TrivyScanner` resolves the binary at construction time and refuses
  to start if it is missing.
* `--exit-code 0` is pinned so the scan is always a *report*, not a
  gate -- gate decisions live in `policy.evaluate_policy`.
* stderr is captured separately and surfaced in `TrivyError` rather
  than mixed into stdout JSON.
* timeout enforced (`config.timeout_sec`, default 600s).
* `--offline-scan` and `--skip-db-update` are first-class flags so
  isolated CI runners never hit the internet.

### Parser

* Schema-tolerant: unknown fields are ignored; non-dict result
  entries are skipped rather than aborting the whole report.
* `Severity.from_str` clamps any unknown string to `UNKNOWN`.
* `SecretFinding.match` is truncated to 240 chars, so a malicious
  artefact cannot make the report unboundedly large via a giant
  matched line.

### Policy

* `Policy` is pure data with conservative defaults
  (`max_critical=0`, `deny_secrets=True`).
* All violations carry a stable `code` so CI can pattern-match on them
  without scraping prose.
* The decision is always one of `PASS|WARN|FAIL`; no "soft" scoring
  paths bypass this.

### Risk model

* Deterministic, no model checkpoints, no remote calls.
* Each subscore has an independent cap so a single category cannot
  drown the total.
* Final score clamped to `[0, 100]`; the operator gets a stable scale.

### LLM advisor

* The advisor sends only *bounded evidence*: top 12 findings,
  severity counts, top 8 secret/misconfig/license findings, and the
  policy violations.  The full report never leaves the host.
* `_coerce_plan` validates the LLM JSON:
  * `cve_ids[*]` -- must match `CVE-\d{4}-\d{4,}` and appear in
    `report.cves()`; otherwise dropped
  * `packages[*]` -- must appear in `report.packages()`; otherwise
    dropped
  * `severity` -- clamped to `UNKNOWN..CRITICAL`
  * `effort` -- clamped to `low|medium|high`
  * `confidence` -- clamped to `[0, 1]`
  * `steps` capped at 12; `actions` per step capped at 6
* On JSON parse failure or LLM transport error the advisor returns a
  deterministic heuristic plan with `fallback=True`.
* The operator can pass `client=None` to disable LLM use entirely
  (the heuristic plan is then always used).

### CLI

* CLI exit code mirrors policy decision (FAIL -> 1, otherwise 0).
* No path in the CLI executes content from a target file.

## Operator responsibilities

1. **Keep the trivy DB current.** Out-of-date DB means missed CVEs.
   In CI use `--skip-db-update` only against a freshly-pulled cache.
2. **Pin the scanner image / binary.** Do not let a supply-chain
   compromise of `trivy` itself silently flip your scan results.
3. **Treat the LLM plan as a triage hint, not ground truth.** The
   validators block invented CVEs but cannot detect a *plausibly
   wrong* claim ("downgrading to 2.16.0 fixes Log4Shell" -- it
   doesn't, see CVE-2021-45046).  Always cross-check against a CVE
   database before acting.
4. **Outbound LLM calls.** The advisor sends scan summaries to
   whatever endpoint `LLMClient` is configured for.  Confirm your
   contract with the LLM provider permits this and prefer a
   self-hosted endpoint.
5. **Run in a read-only namespace.** This package never writes to
   the target, but `trivy` itself may cache layers; isolate that
   cache from production secrets.

## Threats NOT mitigated

* **CVE database completeness.** A vulnerability that NVD / GHSA does
  not yet know about will not appear in the scan.  Trust-boundary
  testing and SBOM provenance are still required.
* **Behavioural attacks at runtime.** This package is static analysis
  of artefacts; runtime defence is `ebpf-detector`'s job.
* **Trivy bugs.** A bug in `trivy` itself can cause false negatives;
  we surface but do not double-check its findings.

## Reporting a vulnerability

Email vinzabe@users.noreply.github.com with:

* Affected file/line
* Reproduction steps
* Suggested mitigation (if any)

Do not file public issues for vulnerabilities.
