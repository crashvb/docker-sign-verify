#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""CLI tests."""

import json
import logging
import os
import shutil

from contextlib import contextmanager
from pathlib import Path
from socket import create_connection
from typing import List, Tuple

import pytest

from OpenSSL import crypto, SSL

from docker_registry_client_async import DockerRegistryClientAsync, Indices
from pytest_docker_registry_fixtures import DockerRegistrySecure
from _pytest.logging import LogCaptureFixture

from docker_sign_verify.gpgsigner import GPGSigner
from docker_sign_verify.scripts.docker_sign import cli

from .conftest import _pytestmark, TypingKnownGoodImage
from .test_gpgsigner import gpgsigner

LOGGER = logging.getLogger(__name__)

pytestmark = _pytestmark


def get_certificate_chain(address: Tuple[str, int]) -> List[str]:
    """Retrieves the PEM encoded certificate change being served at a given address."""
    result = []
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    with create_connection(address) as socket:
        connection = SSL.Connection(context, socket)
        connection.set_connect_state()
        connection.do_handshake()
        for _, certificate in enumerate(connection.get_peer_cert_chain()):
            buffer = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
            result.append(buffer.decode("utf-8"))
    return result


@contextmanager
def ca_trust_store(path: Path):
    """Context manager to globally define the DRCA CA trust store."""
    key = "DRCA_CACERTS"
    old = os.environ.get(key, None)
    os.environ[key] = str(path)
    yield None
    if old is not None:
        os.environ[key] = old
    else:
        del os.environ[key]


@contextmanager
def registry_credentials(docker_registry_secure: DockerRegistrySecure, tmp_path: Path):
    """Context manager to globally define the DRCA credentials store."""
    old = DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE

    auth = docker_registry_secure.auth_header["Authorization"].split()[1]
    credentials = {"auths": {docker_registry_secure.endpoint: {"auth": auth}}}
    path = tmp_path.joinpath("config.json")
    with path.open("w") as file:
        file.write(json.dumps(credentials))
    DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE = path
    yield None
    path.unlink(missing_ok=True)
    DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE = old


@contextmanager
def temporary_gpg_homedir(homedir: Path):
    """Conext manager to globally set the GNUPGHOME location."""
    old = GPGSigner.HOMEDIR
    GPGSigner.HOMEDIR = homedir
    yield None
    GPGSigner.HOMEDIR = old


@pytest.mark.online
def test_bad_keyid(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can handle invalid keyids."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure, tmp_path
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
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can handle a forced digest value."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure, tmp_path
    ), temporary_gpg_homedir(gpgsigner.homedir):
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
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can endorse images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure, tmp_path
    ), temporary_gpg_homedir(gpgsigner.homedir):
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
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can sign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure, tmp_path
    ), temporary_gpg_homedir(gpgsigner.homedir):
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
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can sign (implicit) images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure, tmp_path
    ), temporary_gpg_homedir(gpgsigner.homedir):
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
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can resign images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    source = known_good_image["image_name"]
    destination = source.clone()
    destination.digest = None
    destination.tag += __name__

    with ca_trust_store(docker_registry_secure.cacerts), registry_credentials(
        docker_registry_secure, tmp_path
    ), temporary_gpg_homedir(gpgsigner.homedir):
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
@pytest.mark.skip("TODO: Figure out why the hybrid CA trust store is not working.")
def test_unauthorized_destination(
    caplog: LogCaptureFixture,
    clirunner,
    docker_registry_secure: DockerRegistrySecure,
    gpgsigner: GPGSigner,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    # Inject the dockerhub TLS certificate chain into a copy of the CA trust store ...
    path = tmp_path.joinpath("cacerts.withdockerhub")
    shutil.copy(docker_registry_secure.cacerts, path)
    with path.open("a") as file:
        # file.write(ssl.get_server_certificate((Indices.DOCKERHUB, 443)))
        for certificate in get_certificate_chain((Indices.DOCKERHUB, 443)):
            file.write(certificate)

    with ca_trust_store(path), registry_credentials(
        docker_registry_secure, tmp_path
    ), temporary_gpg_homedir(gpgsigner.homedir):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                gpgsigner.keyid,
                str(known_good_image["image_name"]),
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
    clirunner,
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test docker-sign can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    with registry_credentials(docker_registry_secure, tmp_path):
        result = clirunner.invoke(
            cli,
            args=[
                "registry",
                "--keyid",
                "invalidkeyid",
                f"{Indices.DOCKERHUB}/dummy:dummy",
                str(known_good_image["image_name"]),
            ],
            input="\n",
        )

    assert result.exception
    assert "401" in caplog.text
    assert "Unauthorized" in caplog.text
