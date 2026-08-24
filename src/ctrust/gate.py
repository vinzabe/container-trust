"""The admission decision — pure, so it is trivially testable.

Given an image, its attestation (or absence), a trust policy, and an enforcement
mode, decide admit/deny and WHY. Break-glass forces admission but is only honored
with a non-empty reason, and the decision records that it was bypassed.
"""
from __future__ import annotations

import dataclasses

from .model import Attestation, Image, Mode, TrustPolicy


@dataclasses.dataclass(frozen=True, slots=True)
class Decision:
    admitted: bool
    mode: Mode
    reasons: tuple[str, ...]      # why it violated (empty if fully trusted)
    break_glass: bool = False

    @property
    def compliant(self) -> bool:
        """True if the image would pass even under BLOCK (no violations)."""
        return not self.reasons


def evaluate(image: Image, attestation: Attestation | None,
             policy: TrustPolicy, mode: Mode, *,
             break_glass_reason: str | None = None) -> Decision:
    reasons: list[str] = []

    if not policy.registry_ok(image.registry):
        reasons.append(f"registry '{image.registry}' is not in the trust list")
    if attestation is None:
        reasons.append("no provenance attestation for this digest")
    else:
        if attestation.digest != image.digest:
            reasons.append("attestation digest does not match the image digest")
        if policy.require_signature and not attestation.signature_verified:
            reasons.append("attestation signature is not verified")
        if not policy.builder_ok(attestation.builder):
            reasons.append(f"builder '{attestation.builder}' is not trusted")
        if not policy.source_ok(attestation.source_repo):
            reasons.append(
                f"source '{attestation.source_repo}' is not a trusted source")

    compliant = not reasons

    # break-glass: only with a reason, and only meaningful when it would deny
    if break_glass_reason:
        return Decision(admitted=True, mode=mode, reasons=tuple(reasons),
                        break_glass=not compliant)

    if compliant:
        return Decision(admitted=True, mode=mode, reasons=())
    # violations exist: only BLOCK actually denies
    admitted = mode is not Mode.BLOCK
    return Decision(admitted=admitted, mode=mode, reasons=tuple(reasons))
