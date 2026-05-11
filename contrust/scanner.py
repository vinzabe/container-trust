"""Subprocess wrapper around `trivy`.

The wrapper:
  * resolves the trivy binary at construction time and refuses to start
    if it is missing,
  * pins the JSON output flag and `--exit-code 0` so the scan is a
    *report*, not a gate,
  * captures stderr separately to surface real failures,
  * supports image / fs / sbom / rootfs targets.

Live `trivy` invocation pulls the vuln DB on first run; in tests we
short-circuit by parsing canned JSON via ``parser.parse_trivy_file``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence

from .findings import ScanReport
from .parser import parse_trivy_json


class TrivyError(RuntimeError):
    pass


class TargetKind(str, Enum):
    IMAGE = "image"
    FS = "fs"
    ROOTFS = "rootfs"
    SBOM = "sbom"


@dataclass
class TrivyConfig:
    binary: str = "trivy"
    timeout_sec: int = 600
    scanners: Sequence[str] = field(
        default_factory=lambda: ["vuln", "secret", "misconfig", "license"]
    )
    severity: Sequence[str] = field(
        default_factory=lambda: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    )
    skip_db_update: bool = False
    offline: bool = False
    extra_args: Sequence[str] = field(default_factory=list)


@dataclass
class TrivyScanner:
    """Run `trivy` and return a normalised ``ScanReport``.

    Construction validates that the binary is on PATH; pass an explicit
    ``binary=`` to point at a non-default location.
    """

    config: TrivyConfig = field(default_factory=TrivyConfig)

    def __post_init__(self) -> None:
        binpath = shutil.which(self.config.binary)
        if not binpath:
            raise TrivyError(
                f"trivy binary {self.config.binary!r} not found on PATH"
            )
        self._binpath = binpath

    def _build_argv(self, kind: TargetKind, target: str) -> List[str]:
        argv = [
            self._binpath, str(kind.value),
            "--quiet",
            "--format", "json",
            "--exit-code", "0",
            "--scanners", ",".join(self.config.scanners),
            "--severity", ",".join(self.config.severity),
        ]
        if self.config.skip_db_update:
            argv.append("--skip-db-update")
        if self.config.offline:
            argv.append("--offline-scan")
        argv.extend(self.config.extra_args)
        argv.append(target)
        return argv

    def scan(self, kind: TargetKind, target: str) -> ScanReport:
        if not target:
            raise TrivyError("scan target must be non-empty")
        argv = self._build_argv(kind, target)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_sec,
                check=False,
                env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired as exc:
            raise TrivyError(f"trivy timed out after {self.config.timeout_sec}s") from exc
        if proc.returncode != 0:
            raise TrivyError(
                f"trivy exited with {proc.returncode}: {proc.stderr.strip()[:400]}"
            )
        if not proc.stdout.strip():
            raise TrivyError("trivy produced empty stdout")
        try:
            blob = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise TrivyError(f"trivy stdout was not JSON: {exc!s}") from exc
        return parse_trivy_json(blob)

    # convenience wrappers
    def scan_image(self, image: str) -> ScanReport:
        return self.scan(TargetKind.IMAGE, image)

    def scan_fs(self, path: str) -> ScanReport:
        return self.scan(TargetKind.FS, path)

    def scan_rootfs(self, path: str) -> ScanReport:
        return self.scan(TargetKind.ROOTFS, path)

    def scan_sbom(self, path: str) -> ScanReport:
        return self.scan(TargetKind.SBOM, path)
