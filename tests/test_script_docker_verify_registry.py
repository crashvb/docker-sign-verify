#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""CLI tests."""

import logging

from copy import deepcopy

import pytest

from _pytest.logging import LogCaptureFixture
from docker_registry_client_async import Indices
from docker_sign_verify import GPGSigner
from docker_sign_verify.scripts.docker_sign import cli as cli_signer
from docker_sign_verify.scripts.docker_verify import cli

from .localregistry import (
    docker_client,
    known_good_image_local,
    known_good_image_remote,
    pytest_registry,
    TypingKnownGoodImage,
)  # Needed for pytest.fixtures
from .test_script_docker_sign_registry import insecure_registry, temporary_gpg_homedir
from .test_gpgsigner import gpgsigner

LOGGER = logging.getLogger(__name__)


def test_empty_args(clirunner):
    """Test docker-verify CLI can be invoked."""
    result = clirunner.invoke(cli, ["registry"], catch_exceptions=False)
    assert "Usage:" in result.stdout
    assert result.exit_code != 0


@pytest.mark.online
def test_invalid_keyid(
    runner,
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-verify can handle signed images with unknown keyids."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_signed"

    with insecure_registry():
        with temporary_gpg_homedir(gpgsigner.homedir):
            result = clirunner.invoke(
                cli_signer,
                args=[
                    "registry",
                    "--keyid",
                    gpgsigner.keyid,
                    str(source),
                    str(destination),
                ],
                input=f"{gpgsigner.passphrase}\n",
            )
            assert not result.exception
            assert "Integrity check passed." in caplog.text
            assert "Created new image" in caplog.text
            assert str(destination) in caplog.text

        caplog.clear()

        result = runner.invoke(cli, args=["registry", str(destination)])
        assert result.exception
        assert "Integrity check passed." in caplog.text
        assert "Verification failed for signature with key_id" in caplog.text
        assert "no public key" in caplog.text


@pytest.mark.online
def test_no_signatures_check_signatures(
    runner, known_good_image_remote: TypingKnownGoodImage, caplog: LogCaptureFixture
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image_remote["image_name"])
    result = runner.invoke(cli, args=["--check-signatures", "registry", image,],)
    assert isinstance(result.exception, SystemExit)
    assert "does not contain any signatures" in caplog.text
    assert "is consistent." not in caplog.text
    assert image in caplog.text


@pytest.mark.online
def test_no_signatures_no_check_signatures(
    runner, known_good_image_remote: TypingKnownGoodImage, caplog: LogCaptureFixture
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image_remote["image_name"])
    result = runner.invoke(cli, args=["--no-check-signatures", "registry", image,],)
    assert not result.exception
    assert "is consistent." in caplog.text
    assert "does not contain any signatures" not in caplog.text
    assert image in caplog.text


@pytest.mark.online
def test_not_found(runner, caplog: LogCaptureFixture):
    """Test docker-verify can handle incorrect image names."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = f"{Indices.DOCKERHUB}/library/python:dummy"
    result = runner.invoke(cli, args=["registry", image])
    assert isinstance(result.exception, SystemExit)
    assert "404" in caplog.text
    assert "Not Found" in caplog.text
    assert image in caplog.text


@pytest.mark.online
def test_signed(
    runner,
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-verify can handle signed images."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_signed"

    with insecure_registry(), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli_signer,
            args=[
                "registry",
                "--keyid",
                gpgsigner.keyid,
                str(source),
                str(destination),
            ],
            input=f"{gpgsigner.passphrase}\n",
        )
        assert not result.exception
        assert "Integrity check passed." in caplog.text
        assert "Created new image" in caplog.text
        assert str(destination) in caplog.text

        caplog.clear()

        result = runner.invoke(cli, args=["registry", str(destination)])
        assert not result.exception
        assert "Integrity check passed." in caplog.text
        assert "Signature check passed." in caplog.text
        assert " is consistent; 1 signature(s) verified." in caplog.text
        assert str(destination) in caplog.text


@pytest.mark.online
def test_unauthorized(runner, caplog: LogCaptureFixture):
    """Test docker-verify can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = f"{Indices.DOCKERHUB}/dummy:dummy"
    result = runner.invoke(cli, args=["registry", image])
    assert isinstance(result.exception, SystemExit)
    assert "401" in caplog.text
    assert "Unauthorized" in caplog.text
    assert image in caplog.text
