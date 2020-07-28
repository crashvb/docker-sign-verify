#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""CLI tests."""

import logging

from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

import pytest

from _pytest.logging import LogCaptureFixture
from docker_registry_client_async import DockerRegistryClientAsync, Indices
from docker_sign_verify.gpgsigner import GPGSigner
from docker_sign_verify.scripts.docker_sign import cli

from .localregistry import (
    docker_client,
    known_good_image_local,
    known_good_image_remote,
    pytest_registry,
    TypingKnownGoodImage,
)  # Needed for pytest.fixtures
from .test_gpgsigner import gpgsigner

LOGGER = logging.getLogger(__name__)


@contextmanager
def insecure_registry():
    """Context manager to globally disable TLS for registry access."""
    old = DockerRegistryClientAsync.DEFAULT_PROTOCOL
    DockerRegistryClientAsync.DEFAULT_PROTOCOL = "http"
    yield None
    DockerRegistryClientAsync.DEFAULT_PROTOCOL = old


@contextmanager
def temporary_gpg_homedir(homedir: Path):
    """Conext manager to globally set the GNUPGHOME location."""
    old = GPGSigner.HOMEDIR
    GPGSigner.HOMEDIR = homedir
    yield None
    GPGSigner.HOMEDIR = old


@pytest.mark.online
def test_bad_keyid(
    clirunner, known_good_image_local: TypingKnownGoodImage, caplog: LogCaptureFixture
):
    """Test docker-sign can handle invalid keyids."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_foobar"

    with insecure_registry():
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                "invalidkeyid",
                str(source),
                str(destination),
            ],
            input="\n",
        )

    assert result.exception
    assert "Integrity check passed." in caplog.text
    assert "Failed to create signature!" in caplog.text


def test_empty_args(clirunner):
    """Test docker-sign CLI can be invoked."""
    result = clirunner.invoke(cli, ["registry"], catch_exceptions=False)
    assert "Usage:" in result.stdout
    assert result.exit_code != 0


@pytest.mark.online
def test_forced_digest_value(
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-sign can handle a forced digest value."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.tag += "_signed"

    with insecure_registry(), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli,
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
    assert (
        "It is not possible to store a signed image to a predetermined digest"
        in caplog.text
    )
    assert "Integrity check passed." in caplog.text
    assert "Created new image" in caplog.text
    assert str(destination) not in caplog.text
    destination.digest = None
    assert str(destination) in caplog.text


@pytest.mark.online
def test_no_signatures_endorse(
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-sign can endorse images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_endorsed"

    with insecure_registry(), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli,
            args=[
                "--signature-type",
                "endorse",
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


@pytest.mark.online
def test_no_signatures_sign(
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-sign can sign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_signed"

    with insecure_registry(), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli,
            args=[
                "--signature-type",
                "sign",
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


@pytest.mark.online
def test_no_signatures_sign_implicit(
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-sign can sign (implicit) images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_signed"

    with insecure_registry(), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli,
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


@pytest.mark.online
def test_no_signatures_resign(
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-sign can resign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_resigned"

    with insecure_registry(), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli,
            args=[
                "--signature-type",
                "resign",
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


@pytest.mark.online
def test_unauthorized_destination(
    clirunner,
    known_good_image_local: TypingKnownGoodImage,
    gpgsigner: GPGSigner,
    caplog: LogCaptureFixture,
):
    """Test docker-sign can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image_local["image_name"]
    destination = deepcopy(source)
    destination.digest = None
    destination.tag += "_foobar"

    with insecure_registry(), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                gpgsigner.keyid,
                str(known_good_image_local["image_name"]),
                f"{Indices.DOCKERHUB}/dummy:dummy",
            ],
            input=f"{gpgsigner.passphrase}\n",
        )

    assert result.exception
    assert "Integrity check passed." in caplog.text
    assert "401" in caplog.text
    assert "Unauthorized" in caplog.text


@pytest.mark.online
def test_unauthorized_source(
    clirunner, known_good_image_local: TypingKnownGoodImage, caplog: LogCaptureFixture,
):
    """Test docker-sign can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    with insecure_registry():
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                "invalidkeyid",
                f"{Indices.DOCKERHUB}/dummy:dummy",
                str(known_good_image_local["image_name"]),
            ],
            input="\n",
        )

    assert result.exception
    assert "401" in caplog.text
    assert "Unauthorized" in caplog.text
