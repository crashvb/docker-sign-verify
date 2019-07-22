#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""ImageConfig tests."""

import copy

from typing import List

import pytest

from docker_sign_verify import FormattedSHA256, ImageConfig, Signer

from .stubs import _signer_for_signature, FakeSigner
from .testutils import get_test_data


@pytest.fixture
def json_bytes(request) -> bytes:
    """Provides a sample image configuration."""
    return get_test_data(request, __name__, "config.json")


@pytest.fixture
def json_bytes_canonical(request) -> bytes:
    """Provides the canonical form of the sample image configuration."""
    return get_test_data(request, __name__, "config_canonical.json")


@pytest.fixture
def json_bytes_signed(request) -> bytes:
    """Provides a sample image configuration with a single PGP signature."""
    return get_test_data(request, __name__, "config_signed.json")


@pytest.fixture
def json_bytes_signed_canonical(request) -> bytes:
    """Provides the canonical form of the signed sample image configuration."""
    return get_test_data(request, __name__, "config_signed_canonical.json")


@pytest.fixture
def config_digest(request) -> FormattedSHA256:
    """Provides the digest value of the sample image configuration."""
    return FormattedSHA256.parse(
        get_test_data(request, __name__, "config.json.digest", "r")
    )


@pytest.fixture
def config_digest_canonical(request) -> FormattedSHA256:
    """Provides the digest value of canonical form of the sample image configuration."""
    return FormattedSHA256.parse(
        get_test_data(request, __name__, "config_canonical.json.digest", "r")
    )


@pytest.fixture
def config_digest_signed(request) -> FormattedSHA256:
    """"Provides the digest value of the signed sample image configuration."""
    return FormattedSHA256.parse(
        get_test_data(request, __name__, "config_signed.json.digest", "r")
    )


@pytest.fixture
def config_digest_signed_canonical(request) -> FormattedSHA256:
    """Provides the digest value of the canonical form of the signed sample image configuration."""
    return FormattedSHA256.parse(
        get_test_data(request, __name__, "config_signed_canonical.json.digest", "r")
    )


@pytest.fixture
def image_layers() -> List:
    """Provides the list of layer identifiers contained in the sample image configuration."""
    return [
        "sha256:94b2db70f7476c98f4c4a1b7a922136e0c5600d2d74905407ad364dcca2bf852",
        "sha256:22426f366c51f26105aa9a6c6c9aea9fff0f21b7aabfc97870727577edaa3260",
    ]


@pytest.fixture
def image_config(json_bytes: bytes) -> ImageConfig:
    """Provides an ImageConfig instance for the sample image configuration."""
    # Do not use caching; get a new instance for each test
    return ImageConfig(json_bytes)


@pytest.fixture
def image_config_signed(json_bytes_signed: bytes) -> ImageConfig:
    """Provides an ImageConfig instance for the signed sample image configuration."""
    # Do not use caching; get a new instance for each test
    return ImageConfig(json_bytes_signed)


@pytest.fixture
def signature(request) -> str:
    """Provides the PGP signature value used in the signed sample image configuration."""
    return get_test_data(request, __name__, "signature", "r")


def test_init(image_config: ImageConfig, image_config_signed: ImageConfig):
    """Test that signed and unsigned configurations can be instantiated."""
    assert image_config
    assert image_config_signed


def test_str(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes: bytes,
    json_bytes_signed: bytes,
):
    """Test __str__ pass-through for signed and unsigned configurations (with encoding)."""
    assert str(image_config) == json_bytes.decode("utf-8")
    assert str(image_config_signed) == json_bytes_signed.decode("utf-8")


def test_get_config(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes: bytes,
    json_bytes_signed: bytes,
):
    """Test get_config() pass-through for signed and unsigned configurations."""
    assert image_config.get_config() == json_bytes
    assert image_config_signed.get_config() == json_bytes_signed


def test_get_config_canonical(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes_canonical: bytes,
    json_bytes_signed_canonical: bytes,
):
    """Test the canonical form for signed and unsigned configurations."""
    assert image_config.get_config_canonical() == json_bytes_canonical
    assert image_config_signed.get_config_canonical() == json_bytes_signed_canonical


def test_get_config_digest(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest: str,
    config_digest_signed: str,
):
    """Test digest calculation for signed and unsigned configurations."""
    assert image_config.get_config_digest() == config_digest
    assert image_config_signed.get_config_digest() == config_digest_signed


def test_get_config_digest_canonical(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest_canonical: str,
    config_digest_signed_canonical: str,
):
    """Test canonical digest calculation for signed and unsigned configurations."""
    assert image_config.get_config_digest_canonical() == config_digest_canonical
    assert (
        image_config_signed.get_config_digest_canonical()
        == config_digest_signed_canonical
    )


def test_get_image_layers(
    image_config: ImageConfig, image_config_signed: ImageConfig, image_layers: List
):
    """Test image layer preservation for signed and unsigned configurations."""
    assert image_config.get_image_layers() == image_layers
    assert image_config_signed.get_image_layers() == image_layers


def test_get_signature_list(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest_canonical: str,
    signature: str,
):
    """Test signature data parsing for signed and unsigned configurations."""
    signatures_signed = image_config_signed.get_signature_list()
    assert len(signatures_signed) == 1
    assert signatures_signed[0]["digest"] == config_digest_canonical
    assert signatures_signed[0]["signature"] == signature

    signatures_unsigned = image_config.get_signature_list()
    assert not signatures_unsigned


def test_sign(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest_canonical: str,
    signature: str,
):
    """Test configuration signing for signed and unsigned configurations."""

    signer = FakeSigner()
    assert image_config.sign(signer) == signer.signature_value
    assert image_config_signed.sign(signer) == signer.signature_value

    # Previously unsigned configurations should now contain the new signature.
    assert b"BEGIN FAKE SIGNATURE" in image_config.get_config()
    signatures = image_config.get_signature_list()
    assert len(signatures) == 1
    assert signatures[0]["digest"] == config_digest_canonical
    assert signatures[0]["signature"] == signer.signature_value

    # Previously signed configurations should now contain the original signature(s) and the new signature.
    assert b"BEGIN FAKE SIGNATURE" in image_config_signed.get_config()
    assert b"BEGIN PGP SIGNATURE" in image_config_signed.get_config()
    signatures_signed = image_config_signed.get_signature_list()
    assert len(signatures_signed) == 2
    assert signatures_signed[0]["digest"] == config_digest_canonical
    assert signatures_signed[0]["signature"] == signature
    assert signatures_signed[1]["digest"] == config_digest_canonical
    assert signatures_signed[1]["signature"] == signer.signature_value


def test_sign_endorse(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest_canonical: str,
    config_digest_signed_canonical: str,
    signature: str,
):
    """Test configuration endorsement for signed and unsigned configurations."""

    signer = FakeSigner()
    assert image_config.sign(signer, True) == signer.signature_value
    assert image_config_signed.sign(signer, True) == signer.signature_value

    # Previously unsigned configurations should now contain the new signature.
    assert b"BEGIN FAKE SIGNATURE" in image_config.get_config()
    signatures = image_config.get_signature_list()
    assert len(signatures) == 1
    assert signatures[0]["digest"] == config_digest_canonical
    assert signatures[0]["signature"] == signer.signature_value

    # Previously signed configurations should now contain the original signature(s) and the new signature.
    assert b"BEGIN FAKE SIGNATURE" in image_config_signed.get_config()
    assert b"BEGIN PGP SIGNATURE" in image_config_signed.get_config()
    signatures_signed = image_config_signed.get_signature_list()
    assert len(signatures_signed) == 2
    assert signatures_signed[0]["digest"] == config_digest_canonical
    assert signatures_signed[0]["signature"] == signature
    assert signatures_signed[1]["digest"] == config_digest_signed_canonical
    assert signatures_signed[1]["signature"] == signer.signature_value


def test_sign_endorse_recursive(image_config: ImageConfig):
    """Test interlaced signatures and endorsements."""

    # Stack representation of a binary tree
    stack = [copy.deepcopy(image_config)]
    iterations = 6
    # Breadth first traversal ...
    for i in range(iterations):
        for _ in range(len(stack)):
            # Validate the signature / endorsement permutations of the first entry on the stack ...
            signatures = stack[0].get_signature_list()
            assert len(signatures) == i
            for sig, signature in enumerate(signatures):
                if "Signing" in signature["signature"] or sig == 0:
                    # Signature digests should be independent of the number of signatures
                    assert (
                        signature["digest"]
                        == image_config.get_config_digest_canonical()
                    )
                else:
                    # Endorsement digests should include all entities of a lower order
                    temp = copy.deepcopy(stack[0])
                    temp.set_signature_list(temp.get_signature_list()[:sig])
                    assert signature["digest"] == temp.get_config_digest_canonical()

            def append_new_image_config(
                config: ImageConfig, endorse: bool = False, iteration=i
            ):
                signer = FakeSigner(
                    "<<< {0} {1}: {2} >>>".format(
                        iteration,
                        "Endorsing" if endorse else "Signing",
                        config.get_config_digest_canonical(),
                    )
                )
                config.sign(signer, endorse)
                stack.append(config)

            # TODO: Add optimization to stop appending to the stack if they will never be validated

            # Push two more image configurations on to the stack: one signed, one endorsed ...
            append_new_image_config(copy.deepcopy(stack[0]))
            append_new_image_config(stack.pop(0), True)


def test_verify_signatures(image_config: ImageConfig):
    """Test signature verification for signed and unsigned configurations."""

    # Unsigned configurations should explicitly raise an exception.
    with pytest.raises(Exception) as exception:
        image_config.verify_signatures()
    assert str(exception.value) == "Image does not contain any signatures!"

    # Sign a previously unsigned configuration, so that only the new signature type is present.
    # Note: It is not trivial to embed "known" GPG / PKI signature types, as assumptions about the
    #       test environment are difficult to make.
    image_config.sign(FakeSigner())

    # An exception should be raised if the provider for a signature type is not known
    with pytest.raises(Exception) as exception:
        image_config.verify_signatures()
    assert str(exception.value) == "Unsupported signature type!"

    # Replace the class method for resolving signature providers ...
    original_method = Signer.for_signature
    Signer.for_signature = _signer_for_signature

    # The Signer's verify() method should be invoked.
    assert image_config.verify_signatures()["results"] == [
        {"type": "fake", "valid": True}
    ]

    # Restore the original class method
    Signer.for_signature = original_method


def test_verify_signatures_manipulated_signatures(image_config: ImageConfig):
    """Test that signature verification detects manipulated signatures."""

    # Add a single signature ...
    signer = FakeSigner()
    assert image_config.sign(signer) == signer.signature_value

    # Replace the class method for resolving signature providers ...
    original_method = Signer.for_signature
    Signer.for_signature = _signer_for_signature

    # Sanity check
    assert image_config.verify_signatures()["results"][0]["valid"] is True

    # Modify the digest value of the (first) signature ...
    signatures = image_config.get_signature_list()
    temp = copy.deepcopy(signatures)
    temp[0]["digest"] = "tampertampertamper"
    image_config.set_signature_list(temp)

    # An exception should be raised if digest value from the signature does not match the canonical digest of the image
    # configuration (without any signatures).
    with pytest.raises(Exception) as exception:
        image_config.verify_signatures()
    assert str(exception.value).startswith("Image config canonical digest mismatch:")

    # Restore the unmodified signature and endorse ...
    image_config.set_signature_list(signatures)
    assert image_config.sign(signer, True) == signer.signature_value

    # Sanity check
    assert image_config.verify_signatures()["results"][0]["valid"] is True

    # Modify the digest value of the second signature ...
    signatures = image_config.get_signature_list()
    temp = copy.deepcopy(signatures)
    temp[1]["digest"] = "tampertampertamper"
    image_config.set_signature_list(temp)

    # An exception should be raised if digest value from the signature does not match the canonical digest of the image
    # configuration (including the first signature).
    with pytest.raises(Exception) as exception:
        image_config.verify_signatures()
    assert str(exception.value).startswith("Image config canonical digest mismatch:")

    # Restore the original class method
    Signer.for_signature = original_method


def test_minimal():
    """Test minimal image configuration (for non-conformant labels)k."""

    # Note: At a minimum, [Cc]onfig key must exist with non-null value
    image_config = ImageConfig(b'{"Config":{}}')
    config_digest_canonical = image_config.get_config_digest_canonical()
    signer = FakeSigner()
    assert image_config.sign(signer) == signer.signature_value

    # A signature should always be able to be added ...
    assert b"BEGIN FAKE SIGNATURE" in image_config.get_config()
    signatures = image_config.get_signature_list()
    assert len(signatures) == 1
    assert signatures[0]["digest"] == config_digest_canonical
    assert signatures[0]["signature"] == signer.signature_value
