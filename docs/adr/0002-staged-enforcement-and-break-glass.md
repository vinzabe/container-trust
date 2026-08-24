# 2. Staged enforcement + audited break-glass make failing closed safe

Date: 2026-08-24
Status: Accepted

## Context
A provenance gate that blocks on day one causes an outage the first time a
legitimate-but-unattested image is deployed. Teams respond by disabling the gate —
so the naive "secure" design produces zero security.

## Decision
- Three modes (audit/warn/block) with per-namespace assignment, so a team can
  discover unattested images in warn before enforcing in block, and roll out
  namespace by namespace.
- Break-glass forces admission but ONLY with a non-empty reason, and the decision
  records that a bypass occurred (`break_glass=True`) plus the reason. Break-glass
  on an already-compliant image is not flagged as a bypass (nothing was bypassed).

## Consequences
- The gate can be adopted incrementally without an outage, which means it actually
  gets adopted.
- Every emergency bypass is auditable (`ctrust audit --break-glass`), so
  break-glass is a controlled exception, not a hole.
- Cost: warn/audit modes provide no enforcement. That is the point of staged
  rollout; the mode is explicit per namespace so nobody is in warn by accident.
