#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""CLI tests."""

import logging

import pytest

from docker_registry_client_async import Indices
from pytest_docker_registry_fixtures import DockerRegistrySecure
from _pytest.logging import LogCaptureFixture

from docker_sign_verify.gpgsigner import GPGSigner
from docker_sign_verify.scripts.docker_sign import cli

from .conftest import _pytestmark, TypingKnownGoodImage
from .test_gpgsigner import gpgsigner  # Needed for pytest
from .testutils import ca_trust_store, hybrid_trust_store, registry_credentials

LOGGER = logging.getLogger(__name__)

pytestmark = _pytestmark


@pytest.mark.online
def test_bad_keyid(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can handle invalid keyids."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                "invalidkeyid",
                str(source),
                str(destination),
            ],
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input="invalidpassword\n",
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
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can handle a forced digest value."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                gpgsigner.keyid,
                str(source),
                str(destination),
            ],
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input=f"{gpgsigner.passphrase}\n",
        )

    assert not result.exception
    assert (
        "It is not possible to store a signed image to a predetermined digest"
        in caplog.text
    )
    assert "Integrity check passed." in caplog.text
    assert "Created new image" in caplog.text
    destination.digest = None
    assert str(destination) in caplog.text


@pytest.mark.online
def test_no_signatures_endorse(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can endorse images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
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
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input=f"{gpgsigner.passphrase}\n",
        )

    assert not result.exception
    assert "Integrity check passed." in caplog.text
    assert "Created new image" in caplog.text
    assert str(destination) in caplog.text


@pytest.mark.online
def test_no_signatures_sign(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can sign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
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
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input=f"{gpgsigner.passphrase}\n",
        )

    assert not result.exception
    assert "Integrity check passed." in caplog.text
    assert "Created new image" in caplog.text
    assert str(destination) in caplog.text


@pytest.mark.online
def test_no_signatures_sign_implicit(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can sign (implicit) images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                gpgsigner.keyid,
                str(source),
                str(destination),
            ],
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input=f"{gpgsigner.passphrase}\n",
        )

    assert not result.exception
    assert "Integrity check passed." in caplog.text
    assert "Created new image" in caplog.text
    assert str(destination) in caplog.text


@pytest.mark.online
def test_no_signatures_resign(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can resign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
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
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input=f"{gpgsigner.passphrase}\n",
        )

    assert not result.exception
    assert "Integrity check passed." in caplog.text
    assert "Created new image" in caplog.text
    assert str(destination) in caplog.text


@pytest.mark.online
@pytest.mark.skip("TODO: Figure out why the hybrid CA trust store is not working.")
def test_unauthorized_destination(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    # Using local registry credentials when connecting to dockerhub ...
    with hybrid_trust_store(docker_registry_secure) as path, ca_trust_store(
        path
    ), registry_credentials(docker_registry_secure):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                gpgsigner.keyid,
                str(known_good_image["image_name"]),
                f"{Indices.DOCKERHUB}/dummy:dummy",
            ],
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input=f"{gpgsigner.passphrase}\n",
        )

    assert result.exception
    assert "Integrity check passed." in caplog.text
    assert "401" in caplog.text
    assert "Unauthorized" in caplog.text


@pytest.mark.online
def test_unauthorized_source(
    clirunner,
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    # Using local registry credentials when connecting to dockehub ...
    with registry_credentials(docker_registry_secure):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                gpgsigner.keyid,
                f"{Indices.DOCKERHUB}/dummy:dummy",
                str(known_good_image["image_name"]),
            ],
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input="\n",
        )

    assert result.exception
    assert "401" in caplog.text
    assert "Unauthorized" in caplog.text
