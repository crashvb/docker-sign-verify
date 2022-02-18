#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""PKISigner tests."""

import logging
import os
import tempfile

from time import time

import pytest

from docker_sign_verify import PKISigner, Signer

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


@pytest.fixture()
async def pkisigner(request) -> PKISigner:
    """Provides a PKISigner instance."""
    keypair = tempfile.mkstemp()[1]

    def _remove_keypair():
        os.remove(keypair)

    request.addfinalizer(_remove_keypair)
    signer = PKISigner(keypair_path=keypair, passphrase="testing")
    # pylint: disable=protected-access
    await signer._debug_init_keypair(2048)
    return signer


async def test_for_signature():
    """Tests subclass instantiation."""
    result = Signer.for_signature("PKI SIGNATURE")
    assert result
    assert isinstance(result, PKISigner)


async def test_simple(pkisigner: PKISigner):
    """Test configuration signing and verification using PKI."""

    data = f"TEST DATA: {time()}".encode(encoding="utf-8")
    LOGGER.debug("Using test data: %s", data)

    # Generate a signature for the test data ...
    signature = await pkisigner.sign(data=data)
    assert "PKI SIGNATURE" in signature

    # Verify the generated signature against the test data ...
    result = await pkisigner.verify(data=data, signature=signature)
    assert result.valid
    assert result.keypair_path == pkisigner.keypair_path
    assert result.type == "pki"


async def test_bad_data(pkisigner: PKISigner):
    """Test configuration signing and verification using PKI with bad data."""

    data = f"TEST DATA: {time()}".encode(encoding="utf-8")
    LOGGER.debug("Using test data: %s", data)

    # Generate a signature for the test data ...
    signature = await pkisigner.sign(data=data)
    assert "PKI SIGNATURE" in signature

    data += b"tampertampertamper"
    LOGGER.debug("Using tampered data: %s", data)

    # Verify the generated signature against the test data ...
    result = await pkisigner.verify(data=data, signature=signature)
    assert not result.valid
    assert result.keypair_path == pkisigner.keypair_path
    assert result.type == "pki"
