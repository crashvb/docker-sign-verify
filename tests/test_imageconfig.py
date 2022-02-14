#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name,too-many-arguments

"""ImageConfig tests."""

import json
import logging

from copy import deepcopy
from typing import List

import pytest

from docker_registry_client_async import FormattedSHA256
from pytest_gnupg_fixtures import GnuPGKeypair

from docker_sign_verify import (
    DigestMismatchError,
    GPGSigner,
    ImageConfig,
    NoSignatureError,
    SignatureTypes,
)
from docker_sign_verify.imageconfig import ImageConfigSignatureEntry

from .stubs import FakeSigner
from .testutils import get_test_data

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


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
    """ "Provides the digest value of the signed sample image configuration."""
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


async def test___init__(image_config: ImageConfig, image_config_signed: ImageConfig):
    """Test that signed and unsigned configurations can be instantiated."""
    assert image_config
    assert image_config_signed


async def test___bytes__(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes: bytes,
    json_bytes_signed: bytes,
):
    """Test __bytes__ pass-through for signed and unsigned configurations (with encoding)."""
    assert bytes(image_config) == json_bytes
    assert bytes(image_config_signed) == json_bytes_signed


async def test___str__(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes: bytes,
    json_bytes_signed: bytes,
):
    """Test __str__ pass-through for signed and unsigned configurations (with encoding)."""
    assert str(image_config) == json_bytes.decode("utf-8")
    assert str(image_config_signed) == json_bytes_signed.decode("utf-8")


async def test__get_labels():
    """Test that labels are able to be retrieved."""
    # Uppercase 'C'
    assert ImageConfig._get_labels(json.loads('{"Config":{"Labels":{"x":"5"}}}')) == {
        "x": "5"
    }

    # Lowercase 'C'
    assert ImageConfig._get_labels(json.loads('{"config":{"Labels":{"x":"5"}}}')) == {
        "x": "5"
    }

    # Missing 'Labels'
    assert ImageConfig._get_labels(json.loads('{"Config":{}}')) == {}


async def test__normalize():
    """Test that signed and unsigned configuration can be normalized."""
    # Missing 'Labels'
    assert ImageConfig._normalize(json.loads('{"Config":{}}')) == {
        "Config": {"Labels": {"signatures": "[]"}}
    }

    # Missing 'signatures'
    assert ImageConfig._normalize(json.loads('{"Config":{"Labels":{"x":"5"}}}')) == {
        "Config": {"Labels": {"signatures": "[]", "x": "5"}}
    }

    # Empty 'signatures'
    assert ImageConfig._normalize(
        json.loads('{"Config":{"Labels":{"signatures":"[]","x":"5"}}}')
    ) == {"Config": {"Labels": {"signatures": "[]", "x": "5"}}}

    # Existing 'signatures'
    assert ImageConfig._normalize(
        json.loads('{"Config":{"Labels":{"signatures":"[{\\"y\\":\\"4\\"}]","x":"5"}}}')
    ) == {"Config": {"Labels": {"signatures": '[{"y":"4"}]', "x": "5"}}}


async def test_get_bytes(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes: bytes,
    json_bytes_signed: bytes,
):
    """Test get_bytes() pass-through for signed and unsigned configurations."""
    assert image_config.get_bytes() == json_bytes
    assert image_config_signed.get_bytes() == json_bytes_signed


async def test_get_bytes_canonical(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes_canonical: bytes,
    json_bytes_signed_canonical: bytes,
):
    """Test the canonical form for signed and unsigned configurations."""
    assert image_config.get_bytes_canonical() == json_bytes_canonical
    assert image_config_signed.get_bytes_canonical() == json_bytes_signed_canonical


async def test_get_digest(
    config_digest: str,
    config_digest_signed: str,
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
):
    """Test digest calculation for signed and unsigned configurations."""
    assert image_config.get_digest() == config_digest
    assert image_config_signed.get_digest() == config_digest_signed


async def test_get_digest_canonical(
    config_digest_canonical: str,
    config_digest_signed_canonical: str,
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
):
    """Test canonical digest calculation for signed and unsigned configurations."""
    assert image_config.get_digest_canonical() == config_digest_canonical
    assert image_config_signed.get_digest_canonical() == config_digest_signed_canonical


async def test_get_image_layers(
    image_config: ImageConfig, image_config_signed: ImageConfig, image_layers: List
):
    """Test image layer preservation for signed and unsigned configurations."""
    assert image_config.get_image_layers() == image_layers
    assert image_config_signed.get_image_layers() == image_layers


async def test_clear_signature_list(
    image_config: ImageConfig, image_config_signed: ImageConfig
):
    """Test signature data parsing for signed and unsigned configurations."""
    image_config_signed.clear_signature_list()
    assert not image_config_signed.get_signature_list()

    image_config.clear_signature_list()
    signatures_unsigned = image_config.get_signature_list()
    assert not signatures_unsigned


async def test_get_signature_list(
    config_digest_canonical: str,
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    signature: str,
):
    """Test signature data parsing for signed and unsigned configurations."""
    signatures_signed = image_config_signed.get_signature_list()
    assert len(signatures_signed) == 1
    assert signatures_signed[0].digest == config_digest_canonical
    assert signatures_signed[0].signature == signature

    signatures_unsigned = image_config.get_signature_list()
    assert not signatures_unsigned


# TODO: Scale out these tests to use all types of signers ...
async def test_sign(
    config_digest_canonical: str,
    gnupg_keypair: GnuPGKeypair,
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    signature: str,
):
    """Test configuration signing for signed and unsigned configurations."""

    signer = GPGSigner(
        keyid=gnupg_keypair.keyid,
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )
    sig = await image_config.sign(signer=signer)
    assert "PGP SIGNATURE" in sig
    sig_signed = await image_config_signed.sign(signer=signer)
    assert "PGP SIGNATURE" in sig_signed

    # Previously unsigned configurations should now contain the new signature.
    signatures = image_config.get_signature_list()
    assert len(signatures) == 1
    assert signatures[0].digest == config_digest_canonical
    assert signatures[0].signature == sig

    # Previously signed configurations should now contain the original signature(s) and the new signature.
    assert image_config_signed.get_bytes().count(b"BEGIN PGP SIGNATURE") == 2
    signatures_signed = image_config_signed.get_signature_list()
    assert len(signatures_signed) == 2
    assert signatures_signed[0].digest == config_digest_canonical
    assert signatures_signed[0].signature == signature
    assert signatures_signed[1].digest == config_digest_canonical
    assert signatures_signed[1].signature == sig_signed


async def test_sign_endorse(
    config_digest_canonical: str,
    config_digest_signed_canonical: str,
    gnupg_keypair: GnuPGKeypair,
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    signature: str,
):
    """Test configuration endorsement for signed and unsigned configurations."""

    signer = GPGSigner(
        keyid=gnupg_keypair.keyid,
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )
    sig = await image_config.sign(signature_type=SignatureTypes.ENDORSE, signer=signer)
    assert "PGP SIGNATURE" in sig
    sig_signed = await image_config_signed.sign(
        signature_type=SignatureTypes.ENDORSE, signer=signer
    )
    assert "PGP SIGNATURE" in sig_signed

    # Previously unsigned configurations should now contain the new signature.
    signatures = image_config.get_signature_list()
    assert len(signatures) == 1
    assert signatures[0].digest == config_digest_canonical
    assert signatures[0].signature == sig

    # Previously signed configurations should now contain the original signature(s) and the new signature.
    assert image_config_signed.get_bytes().count(b"BEGIN PGP SIGNATURE") == 2
    signatures_signed = image_config_signed.get_signature_list()
    assert len(signatures_signed) == 2
    assert signatures_signed[0].digest == config_digest_canonical
    assert signatures_signed[0].signature == signature
    assert signatures_signed[1].digest == config_digest_signed_canonical
    assert signatures_signed[1].signature == sig_signed


async def test_sign_resign(
    config_digest_canonical: str,
    gnupg_keypair: GnuPGKeypair,
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
):
    """Test configuration resigning for signed and unsigned configurations."""

    signer = GPGSigner(
        keyid=gnupg_keypair.keyid,
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )
    sig = await image_config.sign(signature_type=SignatureTypes.RESIGN, signer=signer)
    assert "PGP SIGNATURE" in sig
    sig_signed = await image_config_signed.sign(
        signature_type=SignatureTypes.RESIGN, signer=signer
    )
    assert "PGP SIGNATURE" in sig_signed

    # Previously unsigned configurations should now contain the new signature.
    signatures = image_config.get_signature_list()
    assert len(signatures) == 1
    assert signatures[0].digest == config_digest_canonical
    assert signatures[0].signature == sig

    # Previously signed configurations should now contain (only) the new signature.
    assert image_config_signed.get_bytes().count(b"BEGIN PGP SIGNATURE") == 1
    signatures_signed = image_config_signed.get_signature_list()
    assert len(signatures_signed) == 1
    assert signatures[0].digest == config_digest_canonical
    assert signatures[0].signature == sig_signed


async def test_sign_endorse_recursive(image_config: ImageConfig):
    """Test interlaced signatures and endorsements."""

    # Stack representation of a ternary tree
    stack = [{"name": "?-Unsigned", "image_config": image_config.clone()}]
    LOGGER.debug("Unsigned Canonical Digest: %s", image_config.get_digest_canonical())

    async def append_new_image_config(
        *,
        config: ImageConfig,
        signature_type: SignatureTypes = SignatureTypes.SIGN,
        iteration,
    ):
        action = f"X{signature_type.name}"
        signer = FakeSigner(f"[{iteration}-{action: <8}: {{0}}]")
        await config.sign(signature_type=signature_type, signer=signer)
        stack.append({"name": f"{iteration}-{action}", "image_config": config})

    iterations = 6
    # Breadth first traversal ...
    for i in range(iterations):
        LOGGER.debug("Iteration %d", i)
        for _ in range(len(stack)):
            frame = stack[0]
            LOGGER.debug("  Checking %s", frame["name"])
            # Validate the signature / endorsement permutations of the first entry on the stack ...
            signatures = frame["image_config"].get_signature_list()

            flat_list = "".join([signature.signature for signature in signatures])
            if f"X{SignatureTypes.RESIGN.name}" in flat_list:
                # Too lazy to calculate how many signatures were removed ...
                assert len(signatures) <= i
            else:
                assert len(signatures) == i

            for sig, signature in enumerate(signatures):
                LOGGER.debug("    %s", signature.signature)
                if f"X{SignatureTypes.ENDORSE.name}" in signature.signature:
                    # Endorsement digests should include all entities of a lower order.
                    temp = frame["image_config"].clone()
                    temp.set_signature_list(signatures=temp.get_signature_list()[:sig])
                    assert signature.digest == temp.get_digest_canonical()
                    assert temp.get_digest_canonical() in signature.signature
                else:
                    # Signature digests should be independent of the number of signatures.
                    # Re-signed images should always contain 1 signature.
                    assert signature.digest == image_config.get_digest_canonical()
                    assert image_config.get_digest_canonical() in signature.signature

            # Unshift the first image configuration, append three more image configurations on to the stack: ...
            # ... one signed ...
            await append_new_image_config(
                config=frame["image_config"].clone(), iteration=i
            )
            # ... one endorsed ...
            await append_new_image_config(
                config=frame["image_config"].clone(),
                signature_type=SignatureTypes.ENDORSE,
                iteration=i,
            )
            # ... one resigned ...
            await append_new_image_config(
                config=stack.pop(0).get("image_config"),
                signature_type=SignatureTypes.RESIGN,
                iteration=i,
            )


async def test_verify_signatures(
    config_digest_canonical: str, gnupg_keypair: GnuPGKeypair, image_config: ImageConfig
):
    """Test signature verification for signed and unsigned configurations."""

    signer = GPGSigner(
        keyid=gnupg_keypair.keyid,
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )

    # Unsigned configurations should explicitly raise an exception.
    with pytest.raises(NoSignatureError) as exception:
        await image_config.verify_signatures()
    assert str(exception.value) == "Image does not contain any signatures!"

    # Sign a previously unsigned configuration, so that only the new signature type is present.
    signature = await image_config.sign(signer=signer)

    # Attempt to verify the signatures using the default trust store ...
    response = await image_config.verify_signatures()
    assert len(response.signatures) == 1
    assert response.signatures[0].digest == config_digest_canonical
    assert response.signatures[0].signature == signature
    assert not response.results[0].valid

    # Verify the signatures using a good trust store ...
    response = await image_config.verify_signatures(
        signer_kwargs={GPGSigner.__name__: {"homedir": gnupg_keypair.gnupg_home}}
    )
    assert len(response.signatures) == 1
    assert response.signatures[0].digest == config_digest_canonical
    assert response.signatures[0].signature == signature
    assert response.results[0].valid


async def test_verify_signatures_manipulated_signatures(
    gnupg_keypair: GnuPGKeypair, image_config: ImageConfig
):
    """Test that signature verification detects manipulated signatures."""

    signer = GPGSigner(
        keyid=gnupg_keypair.keyid,
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )

    # Add a single signature ...
    await image_config.sign(signer=signer)
    response = await image_config.verify_signatures(
        signer_kwargs={GPGSigner.__name__: {"homedir": gnupg_keypair.gnupg_home}}
    )
    assert response.results[0].valid

    # Modify the digest value of the (first) signature ...
    signatures = image_config.get_signature_list()
    temp = deepcopy(signatures)
    temp[0] = ImageConfigSignatureEntry(
        digest=FormattedSHA256.calculate(b"tampertampertamper"),
        signature=temp[0].signature,
    )
    image_config.set_signature_list(signatures=temp)

    # An exception should be raised if digest value from the signature does not match the canonical digest of the image
    # configuration (without any signatures).
    with pytest.raises(DigestMismatchError) as exception:
        await image_config.verify_signatures()
    assert str(exception.value).startswith("Image config canonical digest mismatch:")

    # Restore the unmodified signature and endorse ...
    image_config.set_signature_list(signatures=signatures)
    await image_config.sign(signature_type=SignatureTypes.ENDORSE, signer=signer)
    response = await image_config.verify_signatures(
        signer_kwargs={GPGSigner.__name__: {"homedir": gnupg_keypair.gnupg_home}}
    )
    assert response.results[0].valid

    # Modify the digest value of the second signature ...
    signatures = image_config.get_signature_list()
    temp = deepcopy(signatures)
    temp[1] = ImageConfigSignatureEntry(
        digest=FormattedSHA256.calculate(b"tampertampertamper"),
        signature=temp[1].signature,
    )
    image_config.set_signature_list(signatures=temp)

    # An exception should be raised if digest value from the signature does not match the canonical digest of the image
    # configuration (including the first signature).
    with pytest.raises(DigestMismatchError) as exception:
        await image_config.verify_signatures()
    assert str(exception.value).startswith("Image config canonical digest mismatch:")


async def test_minimal(gnupg_keypair: GnuPGKeypair):
    """Test minimal image configuration (for non-conformant labels)k."""

    signer = GPGSigner(
        keyid=gnupg_keypair.keyid,
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )

    # Note: At a minimum, [Cc]onfig key must exist with non-null value
    image_config = ImageConfig(b'{"Config":{}}')
    config_digest_canonical = image_config.get_digest_canonical()
    signature = await image_config.sign(signer=signer)
    assert "PGP SIGNATURE" in signature

    # A signature should always be able to be added ...
    assert b"BEGIN PGP SIGNATURE" in image_config.get_bytes()
    signatures = image_config.get_signature_list()
    assert len(signatures) == 1
    assert signatures[0].digest == config_digest_canonical
    assert signatures[0].signature == signature
