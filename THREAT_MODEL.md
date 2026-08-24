# Threat model & scope

## What this is
The **decision core** of a container-provenance admission control: given an image
and its attestation, decide admit/deny against a trust policy, with staged
enforcement and audited break-glass.

## What this is not
- **Not the signature verifier itself.** `signature_verified` is an input; a real
  deployment computes it with cosign/sigstore upstream and passes the result in.
  This gate decides policy over verified facts; it does not implement crypto.
- **Not the webhook.** The decision is pure; wiring it to a Kubernetes
  ValidatingAdmissionWebhook or a registry gate is the integration step.

## Trust boundaries
- **Attestations are trusted as recorded.** Whoever writes to the store (a CI step)
  is in the trust base. The gate assumes `signature_verified` was computed
  correctly upstream; feeding it a forged "verified" attestation defeats it.
- **The policy and namespace-mode config are trusted inputs** — protect them like
  any other production policy (code review, RBAC on the store).
- **The store is unencrypted** and holds the deployed-image inventory and
  break-glass log; treat it as security-relevant.

## Non-goals / limits
- **Image content scanning** (vulns, malware) — out of scope; pair with a scanner.
- **Runtime enforcement** — this is admission-time only; a container that was
  admitted is not re-checked.
- **Break-glass is honor-system on the reason** — it requires a reason and records
  it, but does not validate that the reason is legitimate. Auditability, not
  prevention, is the control.
- **Registry allowlist matches the reference prefix**, not a verified registry
  identity; combine with signature verification (the primary control) rather than
  relying on the registry field alone.

## Reporting
A logic flaw that admits an image it should deny under `block` is a security bug —
report to **gabejar@usa.com** with the image/attestation/policy.
