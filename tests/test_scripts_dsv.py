#!/usr/bin/env python

# pylint: disable=redefined-outer-name,too-many-arguments,unused-import

"""CLI tests."""

import logging

from pathlib import Path

import pytest

from docker_registry_client_async import Indices
from pytest_docker_registry_fixtures import DockerRegistrySecure
from _pytest.logging import LogCaptureFixture

from docker_sign_verify.gpgsigner import GPGSigner
from docker_sign_verify.scripts.dsv import cli

from .conftest import _pytestmark, TypingKnownGoodImage
from .test_gpgsigner import gpgsigner  # Needed for pytest
from .testutils import (
    drca_cacerts,
    dsv_gpg_datastore,
    hybrid_trust_store,
    drca_credentials_store,
)

LOGGER = logging.getLogger(__name__)

pytestmark = _pytestmark


def test_empty_args(clirunner):
    """Test docker-sign CLI can be invoked."""
    for command in ["copy", "sign", "verify"]:
        result = clirunner.invoke(cli, [command], catch_exceptions=False)
        assert "Usage:" in result.stdout
        assert result.exit_code != 0


@pytest.mark.online
def test_copy_invalid_keyid(
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

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
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

        copy = destination.clone()
        copy.tag += f"{__name__}_copy"

        result = runner.invoke(cli, args=["copy", str(destination), str(copy)])
        assert result.exception
        assert "Integrity check passed." in caplog.text
        assert "Verification failed for signature; keyid=" in caplog.text
        assert "no public key" in caplog.text


@pytest.mark.online
def test_copy_no_signatures_check_signatures(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = runner.invoke(
            cli,
            args=["--check-signatures", "copy", str(source), str(destination)],
        )
    assert isinstance(result.exception, SystemExit)
    assert "does not contain any signatures" in caplog.text
    assert "is consistent." not in caplog.text


@pytest.mark.online
def test_copy_no_signatures_no_check_signatures(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = runner.invoke(
            cli,
            args=[
                "--very-verbose",
                "--no-check-signatures",
                "copy",
                str(source),
                str(destination),
            ],
        )
    assert not result.exception
    assert "is consistent." in caplog.text
    assert "does not contain any signatures" not in caplog.text
    assert "Replicated new image" in caplog.text
    assert str(destination) in caplog.text


@pytest.mark.online
def test_copy_not_found(caplog: LogCaptureFixture, runner):
    """Test docker-verify can handle incorrect image names."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = f"{Indices.DOCKERHUB}/library/python:dummy"
    destination = f"{Indices.DOCKERHUB}/library/python:dummy_copy"
    result = runner.invoke(cli, args=["copy", source, destination])
    assert isinstance(result.exception, SystemExit)
    assert "404" in caplog.text
    assert "Not Found" in caplog.text
    assert source in caplog.text


@pytest.mark.online
def test_copy_signed(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    clirunner,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle signed images."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
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

        copy = destination.clone()
        copy.tag += f"{__name__}_copy"

        with dsv_gpg_datastore(gpgsigner.homedir):
            result = runner.invoke(cli, args=["copy", str(destination), str(copy)])
            assert not result.exception
            assert "Integrity check passed." in caplog.text
            assert "Signature check passed." in caplog.text
            assert " is consistent; 1 signature(s) verified." in caplog.text
            assert "Replicated new image" in caplog.text
            assert str(copy) in caplog.text


@pytest.mark.online
def test_copy_unauthorized(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts):
        result = runner.invoke(cli, args=["copy", str(source), str(destination)])
        assert isinstance(result.exception, SystemExit)
        assert "401" in caplog.text
        assert "Unauthorized" in caplog.text
        assert str(source) in caplog.text


@pytest.mark.online
@pytest.mark.skip("TODO: Figure out why the hybrid CA trust store is not working.")
def test_copy_unauthorized_dockerhub(
    caplog: LogCaptureFixture, docker_registry_secure: DockerRegistrySecure, runner
):
    """Test docker-verify can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = f"{Indices.DOCKERHUB}/dummy:dummy"
    destination = f"{Indices.DOCKERHUB}/dummy:dummy_copy"
    with hybrid_trust_store(docker_registry_secure) as path, drca_cacerts(path):
        result = runner.invoke(cli, args=["copy", source, destination])
        assert isinstance(result.exception, SystemExit)
        assert "401" in caplog.text
        assert "Unauthorized" in caplog.text
        assert source in caplog.text


@pytest.mark.online
def test_sign_bad_keyid(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can handle invalid keyids."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
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


@pytest.mark.online
def test_sign_forced_digest_value(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can handle a forced digest value."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
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
def test_sign_no_signatures_endorse(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can endorse images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
                "--keyid",
                gpgsigner.keyid,
                "--signature-type",
                "endorse",
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
def test_sign_no_signatures_sign(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can sign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
                "--keyid",
                gpgsigner.keyid,
                "--signature-type",
                "sign",
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
def test_sign_no_signatures_sign_implicit(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can sign (implicit) images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
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
def test_sign_no_signatures_resign(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
):
    """Test docker-sign can resign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
                "--keyid",
                gpgsigner.keyid,
                "--signature-type",
                "resign",
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
def test_sign_unauthorized_destination(
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
    with hybrid_trust_store(docker_registry_secure) as path, drca_cacerts(
        path
    ), drca_credentials_store(docker_registry_secure):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
                "--keyid",
                gpgsigner.keyid,
                str(known_good_image.image_name),
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
def test_sign_unauthorized_source(
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
    with drca_credentials_store(docker_registry_secure):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
                "--keyid",
                gpgsigner.keyid,
                f"{Indices.DOCKERHUB}/dummy:dummy",
                str(known_good_image.image_name),
            ],
            env={"DSV_GPG_DATASTORE": str(gpgsigner.homedir)},
            input="\n",
        )

    assert result.exception
    assert "401" in caplog.text
    assert "Unauthorized" in caplog.text


@pytest.mark.online
def test_verify_invalid_keyid(
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

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
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

        with dsv_gpg_datastore(Path("/dev/null")):
            result = runner.invoke(cli, args=["verify", str(destination)])
            assert result.exception
            assert "Integrity check passed." in caplog.text
            assert "Verification failed for signature; keyid=" in caplog.text
            assert "no public key" in caplog.text


@pytest.mark.online
def test_verify_no_signatures_check_signatures(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image.image_name)
    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = runner.invoke(cli, args=["--check-signatures", "verify", image])
    assert isinstance(result.exception, SystemExit)
    assert "does not contain any signatures" in caplog.text
    assert "is consistent." not in caplog.text
    assert image in caplog.text


@pytest.mark.online
def test_verify_no_signatures_no_check_signatures(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image.image_name)
    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = runner.invoke(cli, args=["--no-check-signatures", "verify", image])
    assert not result.exception
    assert "is consistent." in caplog.text
    assert "does not contain any signatures" not in caplog.text
    assert image in caplog.text


@pytest.mark.online
def test_verify_not_found(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle incorrect image names."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = known_good_image.image_name.clone()
    image.digest = None
    image.tag += "_does_not_exist"
    image = str(image)
    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = runner.invoke(cli, args=["verify", image])
        assert isinstance(result.exception, SystemExit)
        assert "404" in caplog.text
        assert "Not Found" in caplog.text
        assert image in caplog.text


@pytest.mark.online
def test_verify_signed(
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

    source = known_good_image.image_name
    destination = source.clone()
    destination.digest = None
    destination.tag += "_signed"

    with drca_cacerts(docker_registry_secure.cacerts), drca_credentials_store(
        docker_registry_secure
    ):
        result = clirunner.invoke(
            cli,
            args=[
                "sign",
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

        with dsv_gpg_datastore(gpgsigner.homedir):
            result = runner.invoke(cli, args=["verify", str(destination)])
            assert not result.exception
            assert "Integrity check passed." in caplog.text
            assert "Signature check passed." in caplog.text
            assert " is consistent; 1 signature(s) verified." in caplog.text
            assert str(destination) in caplog.text


@pytest.mark.online
def test_verify_unauthorized(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    runner,
):
    """Test docker-verify can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = str(known_good_image.image_name)
    with drca_cacerts(docker_registry_secure.cacerts):
        result = runner.invoke(cli, args=["verify", image])
        assert isinstance(result.exception, SystemExit)
        assert "401" in caplog.text
        assert "Unauthorized" in caplog.text
        assert image in caplog.text


@pytest.mark.online
@pytest.mark.skip("TODO: Figure out why the hybrid CA trust store is not working.")
def test_verify_unauthorized_dockerhub(
    caplog: LogCaptureFixture, docker_registry_secure: DockerRegistrySecure, runner
):
    """Test docker-verify can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image = f"{Indices.DOCKERHUB}/dummy:dummy"
    with hybrid_trust_store(docker_registry_secure) as path, drca_cacerts(path):
        result = runner.invoke(cli, args=["verify", image])
        assert isinstance(result.exception, SystemExit)
        assert "401" in caplog.text
        assert "Unauthorized" in caplog.text
        assert image in caplog.text
