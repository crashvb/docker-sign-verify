#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""GPGSigner tests."""

import logging

from time import time

import pytest

from _pytest.logging import LogCaptureFixture

from pytest_gnupg_fixtures import GnuPGKeypair

from docker_sign_verify import GPGSigner, GPGTrust, Signer

from .testutils import get_test_data

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


@pytest.fixture()
async def gpgsigner(gnupg_keypair: GnuPGKeypair) -> GPGSigner:
    """Provides a GPGSinger instance."""

    signer = GPGSigner(
        keyid=gnupg_keypair.fingerprints[1],
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )

    yield signer


async def test__parse_output_key_considered(request):
    """Check for known parsing issues."""
    # pylint: disable=protected-access
    status = get_test_data(request, __name__, "gnupg.stderr.key_considered")

    result = await GPGSigner._parse_output(output=status)
    assert result
    assert result.fingerprint
    assert result.key_id
    assert result.status
    assert result.timestamp
    assert result.trust
    assert result.username


# TODO: Add tests for protected methods ...


async def test_for_signature(caplog: LogCaptureFixture):
    """Tests subclass instantiation."""
    caplog.set_level(logging.FATAL, logger="pretty_bad_protocol")
    result = Signer.for_signature("PGP SIGNATURE")
    assert result
    assert isinstance(result, GPGSigner)


async def test_simple(gnupg_keypair: GnuPGKeypair, gpgsigner: GPGSigner):
    """Test configuration signing and verification using GPG."""

    data = f"TEST DATA: {time()}".encode(encoding="utf-8")
    LOGGER.debug("Using test data: %s", data)

    # Generate a signature for the test data ...
    signature = await gpgsigner.sign(data=data)
    assert "PGP SIGNATURE" in signature

    # Verify the generated signature against the test data ...
    result = await gpgsigner.verify(data=data, signature=signature)
    assert result.fingerprint == gpgsigner.keyid
    assert gpgsigner.keyid.endswith(result.key_id)
    assert "failed" not in result.signer_long
    assert "failed" not in result.signer_short
    assert result.status == "signature valid"
    assert result.timestamp
    assert result.trust == GPGTrust.ULTIMATE.value
    assert result.type == "gpg"
    assert result.username == gnupg_keypair.uids[0]
    assert result.valid


async def test_bad_data(gnupg_keypair: GnuPGKeypair, gpgsigner: GPGSigner):
    """Test configuration signing and verification using GPG with bad data."""

    data = f"TEST DATA: {time()}".encode(encoding="utf-8")
    LOGGER.debug("Using test data: %s", data)

    # Generate a signature for the test data ...
    signature = await gpgsigner.sign(data=data)
    assert "PGP SIGNATURE" in signature

    data += b"tampertampertamper"
    LOGGER.debug("Using tampered data: %s", data)

    # Verify the generated signature against the test data ...
    result = await gpgsigner.verify(data=data, signature=signature)
    assert result.fingerprint is None
    assert gpgsigner.keyid.endswith(result.key_id)
    assert "failed" not in result.signer_long
    assert "failed" not in result.signer_short
    assert result.status != "signature valid"
    assert result.timestamp is None
    assert result.trust == GPGTrust.UNDEFINED.value
    assert result.type == "gpg"
    assert result.username == gnupg_keypair.uids[0]
    assert not result.valid
