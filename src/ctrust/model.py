"""Images, attestations, and the trust store."""
from __future__ import annotations

import dataclasses
import enum


class Mode(enum.Enum):
    """Enforcement stage. The whole point is being able to sit in AUDIT/WARN while
    you find the images that lack provenance, before flipping to BLOCK."""
    AUDIT = "audit"     # record only, always admit
    WARN = "warn"       # admit, but annotate as a violation
    BLOCK = "block"     # deny on violation


@dataclasses.dataclass(frozen=True, slots=True)
class Attestation:
    """A provenance claim about an image digest (SLSA-style, simplified)."""
    digest: str
    builder: str            # who built it (CI identity)
    source_repo: str        # where the source came from
    signature_verified: bool
    predicate_type: str = "https://slsa.dev/provenance/v1"


@dataclasses.dataclass(frozen=True, slots=True)
class Image:
    reference: str          # registry/repo:tag
    digest: str             # sha256:...
    namespace: str = "default"

    @property
    def registry(self) -> str:
        return self.reference.split("/", 1)[0] if "/" in self.reference else ""


@dataclasses.dataclass(frozen=True, slots=True)
class TrustPolicy:
    """What counts as trustworthy."""
    trusted_builders: frozenset[str]
    trusted_source_prefixes: tuple[str, ...]
    trusted_registries: frozenset[str]
    require_signature: bool = True

    def builder_ok(self, builder: str) -> bool:
        return builder in self.trusted_builders

    def source_ok(self, source: str) -> bool:
        return any(source.startswith(p) for p in self.trusted_source_prefixes)

    def registry_ok(self, registry: str) -> bool:
        return not self.trusted_registries or registry in self.trusted_registries
