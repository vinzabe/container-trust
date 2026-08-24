# 3. A pure decision function with a durable decision record

Date: 2026-08-24
Status: Accepted

## Context
Admission logic must be trivially testable (it gates production) and its outcomes
must be reconstructable during an incident.

## Decision
- `gate.evaluate` is a pure function of (image, attestation, policy, mode,
  break_glass) → Decision. No I/O, no clock, fully unit-tested including every
  violation path.
- Every decision — admit or deny, break-glass or not — is written to a SQLite
  store, alongside the attestations themselves.

## Consequences
- The security-critical logic has ~97% test coverage with plain fixtures.
- `deployed_images()` answers "what is running and from where" and
  `break_glass_uses()` answers "who bypassed the gate and why" — both are queries,
  not log-scraping exercises.
- The store schema is versioned and fails loud on mismatch, so an old DB is never
  silently misread.
