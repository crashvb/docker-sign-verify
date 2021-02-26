#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""GPGSigner tests."""

import logging
import os

import pytest

from _pytest.logging import LogCaptureFixture

from pytest_gnupg_fixtures import GnuPGKeypair

from docker_sign_verify import GPGSigner, Signer

from .testutils import get_test_data

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)

if os.environ.get("TRAVIS", "") == "true":
    pytest.skip(
        "TODO: Figure out why GnuPG isn't working under travis", allow_module_level=True
    )


@pytest.fixture()
async def gpgsigner(gnupg_keypair: GnuPGKeypair) -> GPGSigner:
    """Provides a GPGSinger instance."""

    signer = GPGSigner(
        keyid=gnupg_keypair.fingerprints[1],
        passphrase=gnupg_keypair.passphrase,
        homedir=gnupg_keypair.gnupg_home,
    )

    yield signer


async def test__parse_status_key_considered(request):
    """Check for known parsing issues."""
    status = get_test_data(request, __name__, "gnupg.stderr.key_considered")

    # Mainly test that it can parse without choking on KEY_CONSIDERED ...
    # https://github.com/isislovecruft/python-gnupg/issues/224
    # ... is NOT fixed by isislovecruft/python-gnupg:PR#220
    result = await GPGSigner._parse_status(status)
    assert result
    assert result.fingerprint
    assert result.status
    assert result.key_id
    assert result.valid


def test_for_signature(caplog: LogCaptureFixture):
    """Tests subclass instantiation."""
    caplog.set_level(logging.FATAL, logger="pretty_bad_protocol")
    result = Signer.for_signature("PGP SIGNATURE")
    assert result
    assert isinstance(result, GPGSigner)


async def test_simple(gpgsigner: GPGSigner):
    """Test configuration signing and verification using GPG."""

    data = b"TEST DATA"

    # Generate a signature for the test data ...
    signature = await gpgsigner.sign(data)
    assert "PGP SIGNATURE" in signature

    # Verify the generated signature against the test data ...
    result = await gpgsigner.verify(data, signature)
    assert result.fingerprint == gpgsigner.keyid
    assert gpgsigner.keyid.endswith(result.key_id)
    assert result.status == "signature valid"
    assert result.valid


async def test_bad_data(gpgsigner: GPGSigner):
    """Test configuration signing and verification using GPG with bad data."""

    data = b"TEST DATA"

    # Generate a signature for the test data ...
    signature = await gpgsigner.sign(data)
    assert "PGP SIGNATURE" in signature

    data += b"tampertampertamper"

    # Verify the generated signature against the test data ...
    result = await gpgsigner.verify(data, signature)
    assert not result.valid
    assert gpgsigner.keyid.endswith(result.key_id)
    assert result.status == "signature bad"
