"""Load trust policy and per-namespace enforcement modes from JSON.

Per-namespace mode is the staged-rollout lever: keep prod in BLOCK while a new
namespace sits in WARN until its images have attestations.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from .model import Mode, TrustPolicy


@dataclasses.dataclass(frozen=True, slots=True)
class Config:
    policy: TrustPolicy
    default_mode: Mode
    namespace_modes: dict[str, Mode]

    def mode_for(self, namespace: str) -> Mode:
        return self.namespace_modes.get(namespace, self.default_mode)


def load_config(path: Path | str) -> Config:
    d = json.loads(Path(path).read_text())
    policy = TrustPolicy(
        trusted_builders=frozenset(d.get("trusted_builders", [])),
        trusted_source_prefixes=tuple(d.get("trusted_source_prefixes", [])),
        trusted_registries=frozenset(d.get("trusted_registries", [])),
        require_signature=d.get("require_signature", True))
    ns = {k: Mode(v) for k, v in d.get("namespace_modes", {}).items()}
    return Config(policy=policy, default_mode=Mode(d.get("default_mode", "audit")),
                  namespace_modes=ns)
