import pytest

from ctrust.model import Attestation, Image, TrustPolicy

DIGEST = "sha256:" + "a" * 64
BAD_DIGEST = "sha256:" + "b" * 64


@pytest.fixture
def policy():
    return TrustPolicy(
        trusted_builders=frozenset({"github-actions@ci.example.com"}),
        trusted_source_prefixes=("https://github.com/vinzabe/",),
        trusted_registries=frozenset({"ghcr.io"}),
        require_signature=True)


@pytest.fixture
def good_image():
    return Image("ghcr.io/vinzabe/app:1.0", DIGEST, "production")


@pytest.fixture
def good_attestation():
    return Attestation(DIGEST, "github-actions@ci.example.com",
                       "https://github.com/vinzabe/app", True)
