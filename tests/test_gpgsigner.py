#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""GPGSigner tests."""

import logging
import os
import subprocess

from pathlib import Path

import aiofiles
import pytest

from _pytest.logging import LogCaptureFixture
from docker_sign_verify import GPGSigner, Signer

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)

if os.environ.get("TRAVIS", "") == "true":
    pytest.skip(
        "TODO: Figure out why GnuPG isn't working under travis", allow_module_level=True
    )


@pytest.fixture()
async def gpgsigner(request, tmp_path: Path, caplog: LogCaptureFixture) -> GPGSigner:
    """Provides a GPGSinger instance."""

    caplog.set_level(logging.FATAL, logger="gnupg")

    # https://github.com/isislovecruft/python-gnupg/issues/137#issuecomment-459043779
    LOGGER.debug("Initializing GPG home: %s ...", tmp_path)
    tmp_path.chmod(0o700)
    path = tmp_path.joinpath("gpg-agent.conf")
    async with aiofiles.open(path, mode="w") as file:
        await file.write("allow-loopback-pinentry\n")
        await file.write("max-cache-ttl 60\n")
    path.chmod(0o600)

    # TODO: Can this be converted to async?
    def _stop_gpg_agent():
        subprocess.run(
            [
                "/usr/bin/gpg-connect-agent",
                "--homedir",
                str(tmp_path),
                "killagent",
                "/bye",
            ],
            check=True,
        )

    request.addfinalizer(_stop_gpg_agent)
    signer = GPGSigner(
        keyid=None,
        passphrase="testing",
        homedir=tmp_path,
    )
    # pylint: disable=protected-access
    await signer._debug_init_store()

    yield signer


def test_for_signature(caplog: LogCaptureFixture):
    """Tests subclass instantiation."""
    caplog.set_level(logging.FATAL, logger="gnupg")
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
    assert result.valid
    assert gpgsigner.keyid.endswith(result.key_id)
    assert result.status == "signature valid"


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
