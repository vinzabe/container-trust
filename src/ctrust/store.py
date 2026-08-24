"""Attestation store: maps running image digests to their provenance, and records
every admission decision (including break-glass) durably.

This answers the incident-time question "what is deployed and where did it come
from?" and makes break-glass auditable — a bypass with no record is not a control.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path

from .model import Attestation

SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attestations (
    digest TEXT PRIMARY KEY, builder TEXT NOT NULL, source_repo TEXT NOT NULL,
    signature_verified INTEGER NOT NULL, predicate_type TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL,
    digest TEXT NOT NULL, namespace TEXT NOT NULL, admitted INTEGER NOT NULL,
    mode TEXT NOT NULL, reasons TEXT NOT NULL, break_glass_reason TEXT,
    at TEXT NOT NULL);
"""


class Store:
    def __init__(self, path: Path | str) -> None:
        self._c = sqlite3.connect(Path(path), isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(_SCHEMA)
        row = self._c.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self._c.execute("INSERT INTO meta VALUES('schema_version',?)",
                            (str(SCHEMA_VERSION),))
        elif int(row["value"]) != SCHEMA_VERSION:
            raise RuntimeError(f"store schema {row['value']} != {SCHEMA_VERSION}")

    def close(self) -> None:
        self._c.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *e: object) -> None:
        self.close()

    def put_attestation(self, a: Attestation) -> None:
        self._c.execute(
            "INSERT INTO attestations VALUES(?,?,?,?,?) "
            "ON CONFLICT(digest) DO UPDATE SET builder=excluded.builder, "
            "source_repo=excluded.source_repo, "
            "signature_verified=excluded.signature_verified",
            (a.digest, a.builder, a.source_repo, int(a.signature_verified),
             a.predicate_type))

    def get_attestation(self, digest: str) -> Attestation | None:
        r = self._c.execute("SELECT * FROM attestations WHERE digest=?",
                            (digest,)).fetchone()
        if r is None:
            return None
        return Attestation(r["digest"], r["builder"], r["source_repo"],
                           bool(r["signature_verified"]), r["predicate_type"])

    def record_decision(self, *, reference: str, digest: str, namespace: str,
                        admitted: bool, mode: str, reasons: list[str],
                        break_glass_reason: str | None = None) -> None:
        self._c.execute(
            "INSERT INTO decisions(reference,digest,namespace,admitted,mode,"
            "reasons,break_glass_reason,at) VALUES(?,?,?,?,?,?,?,?)",
            (reference, digest, namespace, int(admitted), mode,
             json.dumps(reasons), break_glass_reason,
             dt.datetime.now(dt.UTC).isoformat()))

    def deployed_images(self) -> list[dict[str, str]]:
        return [dict(r) for r in self._c.execute(
            "SELECT DISTINCT reference, digest, namespace FROM decisions "
            "WHERE admitted=1 ORDER BY reference")]

    def break_glass_uses(self) -> list[dict[str, object]]:
        return [dict(r) for r in self._c.execute(
            "SELECT reference,namespace,break_glass_reason,at FROM decisions "
            "WHERE break_glass_reason IS NOT NULL ORDER BY at DESC")]
