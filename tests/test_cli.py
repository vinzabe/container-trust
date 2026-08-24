import json
from pathlib import Path

import pytest

from ctrust.cli import EXIT_ADMIT, EXIT_DENY, main

FIX = Path(__file__).parent / "fixtures"
CFG = str(FIX / "policy.json")
DIGEST = "sha256:" + "a" * 64


def test_admit_flow(tmp_path, capsys):
    store = str(tmp_path / "s.db")
    # register a good attestation, then admit in prod (block mode)
    main(["--store", store, "attest", DIGEST,
          "--builder", "github-actions@ci.example.com",
          "--source", "https://github.com/vinzabe/app", "--signed"])
    capsys.readouterr()
    rc = main(["--store", store, "admit", "ghcr.io/vinzabe/app:1.0", DIGEST,
               "--config", CFG, "--namespace", "production"])
    assert rc == EXIT_ADMIT


def test_deny_missing_attestation_in_prod(tmp_path, capsys):
    rc = main(["--store", str(tmp_path / "s.db"), "admit",
               "ghcr.io/vinzabe/app:1.0", DIGEST, "--config", CFG,
               "--namespace", "production"])
    assert rc == EXIT_DENY   # prod is block mode, no attestation


def test_staging_warn_admits(tmp_path, capsys):
    rc = main(["--store", str(tmp_path / "s.db"), "admit",
               "ghcr.io/vinzabe/app:1.0", DIGEST, "--config", CFG,
               "--namespace", "staging"])
    assert rc == EXIT_ADMIT   # staging is warn mode


def test_break_glass_admits_and_records(tmp_path, capsys):
    store = str(tmp_path / "s.db")
    rc = main(["--store", store, "admit", "ghcr.io/vinzabe/app:1.0", DIGEST,
               "--config", CFG, "--namespace", "production",
               "--break-glass", "incident-42"])
    assert rc == EXIT_ADMIT
    capsys.readouterr()
    main(["--store", store, "audit", "--break-glass", "--json"])
    uses = json.loads(capsys.readouterr().out)
    assert uses and uses[0]["break_glass_reason"] == "incident-42"


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
