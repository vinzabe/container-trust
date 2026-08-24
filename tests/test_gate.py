"""The decision logic: staged enforcement + safe break-glass."""
from ctrust.gate import evaluate
from ctrust.model import Attestation, Image, Mode

DIGEST = "sha256:" + "a" * 64


def test_trusted_image_admitted_in_block(policy, good_image, good_attestation):
    d = evaluate(good_image, good_attestation, policy, Mode.BLOCK)
    assert d.admitted and d.compliant and not d.reasons


def test_missing_attestation_denied_in_block(policy, good_image):
    d = evaluate(good_image, None, policy, Mode.BLOCK)
    assert not d.admitted
    assert any("no provenance" in r for r in d.reasons)


def test_missing_attestation_admitted_in_warn(policy, good_image):
    d = evaluate(good_image, None, policy, Mode.WARN)
    assert d.admitted and not d.compliant   # admitted but flagged


def test_audit_mode_always_admits(policy, good_image):
    d = evaluate(good_image, None, policy, Mode.AUDIT)
    assert d.admitted and d.reasons          # recorded, not enforced


def test_unsigned_attestation_denied(policy, good_image):
    att = Attestation(DIGEST, "github-actions@ci.example.com",
                      "https://github.com/vinzabe/app", signature_verified=False)
    d = evaluate(good_image, att, policy, Mode.BLOCK)
    assert not d.admitted
    assert any("signature" in r for r in d.reasons)


def test_untrusted_builder_denied(policy, good_image):
    att = Attestation(DIGEST, "evil@attacker", "https://github.com/vinzabe/app", True)
    d = evaluate(good_image, att, policy, Mode.BLOCK)
    assert not d.admitted and any("builder" in r for r in d.reasons)


def test_digest_mismatch_denied(policy, good_image):
    att = Attestation("sha256:" + "c" * 64, "github-actions@ci.example.com",
                      "https://github.com/vinzabe/app", True)
    d = evaluate(good_image, att, policy, Mode.BLOCK)
    assert not d.admitted and any("digest" in r for r in d.reasons)


def test_untrusted_registry_denied(policy):
    img = Image("docker.io/evil/app:1.0", DIGEST, "production")
    d = evaluate(img, None, policy, Mode.BLOCK)
    assert any("registry" in r for r in d.reasons)


def test_break_glass_admits_with_reason(policy, good_image):
    d = evaluate(good_image, None, policy, Mode.BLOCK,
                 break_glass_reason="incident-1234 hotfix")
    assert d.admitted and d.break_glass   # forced through, flagged as bypass


def test_break_glass_on_compliant_image_not_flagged(policy, good_image,
                                                    good_attestation):
    d = evaluate(good_image, good_attestation, policy, Mode.BLOCK,
                 break_glass_reason="unnecessary")
    assert d.admitted and not d.break_glass  # nothing was bypassed
