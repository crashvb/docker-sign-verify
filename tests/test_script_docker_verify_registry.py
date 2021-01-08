#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""CLI tests."""

import logging

import pytest

from _pytest.logging import LogCaptureFixture
from docker_registry_client_async import Indices
from pytest_docker_registry_fixtures import DockerRegistrySecure
from docker_sign_verify import GPGSigner
from docker_sign_verify.scripts.docker_sign import cli as cli_signer
from docker_sign_verify.scripts.docker_verify import cli

from .conftest import _pytestmark, TypingKnownGoodImage
from .testutils import (
    ca_trust_store,
    gpg_datastore,
    hybrid_trust_store,
    registry_credentials,
)
from .test_gpgsigner import gpgsigner  # Needed for pytest

LOGGER = logging.getLogger(__name__)

pytestmark = _pytestmark


def test_empty_args(clirunner):
    """Test docker-verify CLI can be invoked."""
    result = clirunner.invoke(cli, ["registry"], catch_exceptions=False)
    assert "Usage:" in result.stdout
    assert result.exit_code != 0


@pytest.mark.online
def test_invalid_keyid(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle signed images with unknown keyids."""
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
            cli_signer,
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

        caplog.clear()

        with gpg_datastore("/dev/null"):
            result = runner.invoke(cli, args=["registry", str(destination)])
            assert result.exception
            assert "Integrity check passed." in caplog.text
            assert "Verification failed for signature with keyid" in caplog.text
            assert "no public key" in caplog.text


@pytest.mark.online
def test_no_signatures_check_signatures(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image["image_name"])
    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
        result = runner.invoke(cli, args=["--check-signatures", "registry", image])
    assert isinstance(result.exception, SystemExit)
    assert "does not contain any signatures" in caplog.text
    assert "is consistent." not in caplog.text
    assert image in caplog.text


@pytest.mark.online
def test_no_signatures_no_check_signatures(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image["image_name"])
    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
        result = runner.invoke(cli, args=["--no-check-signatures", "registry", image])
    assert not result.exception
    assert "is consistent." in caplog.text
    assert "does not contain any signatures" not in caplog.text
    assert image in caplog.text


@pytest.mark.online
def test_not_found(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle incorrect image names."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = known_good_image["image_name"].clone()
    image.digest = None
    image.tag += "_does_not_exist"
    image = str(image)
    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
        result = runner.invoke(cli, args=["registry", image])
        assert isinstance(result.exception, SystemExit)
        assert "404" in caplog.text
        assert "Not Found" in caplog.text
        assert image in caplog.text


@pytest.mark.online
def test_signed(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle signed images."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += "_signed"

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli_signer,
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

        caplog.clear()

        with gpg_datastore(gpgsigner.homedir):
            result = runner.invoke(cli, args=["registry", str(destination)])
            assert not result.exception
            assert "Integrity check passed." in caplog.text
            assert "Signature check passed." in caplog.text
            assert " is consistent; 1 signature(s) verified." in caplog.text
            assert str(destination) in caplog.text


@pytest.mark.online
def test_unauthorized(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image["image_name"])
    with ca_trust_store(docker_registry_secure.cacerts):
        result = runner.invoke(cli, args=["registry", image])
        assert isinstance(result.exception, SystemExit)
        assert "401" in caplog.text
        assert "Unauthorized" in caplog.text
        assert image in caplog.text


@pytest.mark.online
@pytest.mark.skip("TODO: Figure out why the hybrid CA trust store is not working.")
def test_unauthorized_dockerhub(
    caplog: LogCaptureFixture, docker_registry_secure: DockerRegistrySecure, runner
):
    """Test docker-verify can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = f"{Indices.DOCKERHUB}/dummy:dummy"
    with hybrid_trust_store(docker_registry_secure) as path, ca_trust_store(path):
        result = runner.invoke(cli, args=["registry", image])
        assert isinstance(result.exception, SystemExit)
        assert "401" in caplog.text
        assert "Unauthorized" in caplog.text
        assert image in caplog.text
