#!/usr/bin/env python

"""Utility classes."""

import hashlib
import json
import logging
import os

from contextlib import contextmanager
from pathlib import Path
from socket import create_connection
from tempfile import NamedTemporaryFile
from typing import List, Tuple, Union

import aiofiles

from docker_registry_client_async import DockerRegistryClientAsync, Indices
from docker_registry_client_async.formattedsha256 import FormattedSHA256
from pytest_docker_registry_fixtures import DockerRegistrySecure
from OpenSSL import crypto, SSL

from docker_sign_verify.utils import CHUNK_SIZE


LOGGER = logging.getLogger(__name__)


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
def gpg_datastore(path: Path):
    """Context manager to globally define the DRCA GnuPG datastore."""
    key = "DSV_GPG_DATASTORE"
    old = os.environ.get(key, None)
    os.environ[key] = str(path)
    yield None
    if old is not None:
        os.environ[key] = old
    else:
        del os.environ[key]


@contextmanager
def hybrid_trust_store(
    docker_registry_secure: DockerRegistrySecure, dockerhub_url: str = Indices.DOCKERHUB
):
    """
    Creates a temporary CA trust store containing both the secure docker registry and docker hub certificate chains.

    Args:
        docker_registry_secure: The secure docker registry from which to retrieve the credentials.
        dockerhub_url: The url from which to retrieve the dockerhub certificate chain.

    Yields:
        The path to the modified CA trust store.
    """
    tmpfile = NamedTemporaryFile()
    tmpfile.write(docker_registry_secure.cacerts.read_bytes())
    # file.write(ssl.get_server_certificate((dockerhub_url, 443)))
    for certificate in get_certificate_chain((dockerhub_url, 443)):
        tmpfile.write(certificate)
    yield tmpfile.name
    tmpfile.close()


def get_certificate_chain(address: Tuple[str, int]) -> List[bytes]:
    """
    Retrieves the PEM encoded certificate chain being served at a given address.

    Args:
        address: The address from which to retrieve the certificate chain.

    Returns:
        The PEM encoded certificate chain being served at the given address.
    """
    result = []
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    with create_connection(address) as socket:
        connection = SSL.Connection(context, socket)
        connection.set_connect_state()
        connection.do_handshake()
        for _, certificate in enumerate(connection.get_peer_cert_chain()):
            buffer = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
            result.append(buffer)
    return result


def get_test_data_path(request, name) -> Path:
    """Helper method to retrieve the path of test data."""
    return Path(request.fspath).parent.joinpath("data").joinpath(name)


def get_test_data(request, klass, name, mode="rb") -> Union[bytes, str]:
    """Helper method to retrieve test data."""
    key = f"{klass}/{name}"
    result = request.config.cache.get(key, None)
    if result is None:
        path = get_test_data_path(request, name)
        with open(path, mode) as file:
            result = file.read()
            # TODO: How do we / Should we serialize binary data?
            # request.config.cache.set(key, result)
    return result


async def hash_file(path: Path) -> FormattedSHA256:
    """Returns the sha256 digest value for the content of a given file."""
    hasher = hashlib.sha256()
    async with aiofiles.open(path, mode="r+b") as file:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return FormattedSHA256(hasher.hexdigest())


@contextmanager
def registry_credentials(docker_registry_secure: DockerRegistrySecure):
    """
    Context manager to globally define the DRCA credentials store.

    Args:
        docker_registry_secure: The secure docker registry from which to retrieve the credentials.

    Yields:
        The path to the DRCA credentials store.
    """
    old = DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE

    auth = docker_registry_secure.auth_header["Authorization"].split()[1]
    credentials = {"auths": {docker_registry_secure.endpoint: {"auth": auth}}}
    tmpfile = NamedTemporaryFile()
    tmpfile.write(json.dumps(credentials).encode("utf-8"))
    tmpfile.flush()

    DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE = tmpfile.name
    yield DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE
    DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE = old
    tmpfile.close()
