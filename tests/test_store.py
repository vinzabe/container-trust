from ctrust.model import Attestation
from ctrust.store import Store

DIGEST = "sha256:" + "a" * 64


def test_attestation_roundtrip(tmp_path):
    with Store(tmp_path / "s.db") as st:
        st.put_attestation(Attestation(DIGEST, "ci", "https://x/y", True))
        got = st.get_attestation(DIGEST)
        assert got is not None and got.builder == "ci"


def test_missing_attestation_is_none(tmp_path):
    with Store(tmp_path / "s.db") as st:
        assert st.get_attestation("sha256:none") is None


def test_deployed_images_tracked(tmp_path):
    with Store(tmp_path / "s.db") as st:
        st.record_decision(reference="ghcr.io/a:1", digest=DIGEST,
                           namespace="prod", admitted=True, mode="block",
                           reasons=[])
        st.record_decision(reference="ghcr.io/b:1", digest="sha256:x",
                           namespace="prod", admitted=False, mode="block",
                           reasons=["no provenance"])
        deployed = st.deployed_images()
        assert len(deployed) == 1 and deployed[0]["reference"] == "ghcr.io/a:1"


def test_break_glass_recorded(tmp_path):
    with Store(tmp_path / "s.db") as st:
        st.record_decision(reference="ghcr.io/a:1", digest=DIGEST,
                           namespace="prod", admitted=True, mode="block",
                           reasons=["no provenance"],
                           break_glass_reason="incident-1")
        uses = st.break_glass_uses()
        assert len(uses) == 1 and uses[0]["break_glass_reason"] == "incident-1"
