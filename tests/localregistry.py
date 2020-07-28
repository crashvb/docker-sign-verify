#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Utility classes."""

from typing import Dict, Generator, Optional, TypedDict

import docker
import pytest

from docker import DockerClient
from docker_registry_client_async import (
    DockerMediaTypes,
    FormattedSHA256,
    ImageName,
    Indices,
)


class TypingGetTestDataLocal(TypedDict):
    # pylint: disable=missing-class-docstring
    image: str
    tag: str
    digests: Dict[str, FormattedSHA256]
    original_endpoint: Optional[str]
    protocol: Optional[str]


class TypingKnownGoodImage(TypingGetTestDataLocal):
    # pylint: disable=missing-class-docstring
    image_name: ImageName


def get_test_data_local() -> Generator[TypingGetTestDataLocal, None, None]:
    """Dynamically initializes test data for a local mutable registry."""
    images = [
        {
            "image": "{0}/library/python",
            "tag": "3.7.2-slim-stretch",
            "digests": {
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "0005ba40bf87e486d7061ca0112123270e4a6088b5071223c8d467db3dbba908"
                ),
            },
            "original_endpoint": Indices.DOCKERHUB,
            "protocol": "http",
        },
        {
            "image": "{0}/library/busybox",
            "tag": "1.30.1",
            "digests": {
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100"
                ),
            },
            "original_endpoint": Indices.DOCKERHUB,
            "protocol": "http",
        },
    ]
    for image in images:
        yield image


@pytest.fixture(scope="session")
def docker_client() -> DockerClient:
    """Provides a Docker API client."""
    return docker.from_env()


@pytest.fixture(params=get_test_data_local())
def known_good_image_local(request, pytest_registry: str) -> TypingKnownGoodImage:
    """Provides 'known good' metadata for a local image that can be modified."""
    request.param["image"] = request.param["image"].format(pytest_registry)
    manifest_digest = request.param["digests"][
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    ]
    request.param["image_name"] = ImageName.parse(
        f"{request.param['image']}:{request.param['tag']}@{manifest_digest}"
    )
    return request.param


@pytest.fixture(params=get_test_data_local())
def known_good_image_remote(request) -> TypingKnownGoodImage:
    """Provides 'known good' metadata for a remote image that is readonly."""
    request.param["image"] = request.param["image"].format(
        request.param["original_endpoint"]
    )
    manifest_digest = request.param["digests"][
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    ]
    request.param["image_name"] = ImageName.parse(
        f"{request.param['image']}:{request.param['tag']}@{manifest_digest}"
    )
    return request.param


@pytest.fixture(scope="session")
def pytest_registry(docker_client: DockerClient, docker_services) -> str:
    """Provides the endpoint of a local, mutable, docker registry."""
    # Start a local registry using docker-compose ...
    service = "pytest-registry"
    docker_services.start(service)
    public_port = docker_services.wait_for_service(service, 5000)
    endpoint = f"{docker_services.docker_ip}:{public_port}"

    # Replicate select images locally ...
    for item in get_test_data_local():
        repository_src = item["image"].format(item["original_endpoint"])
        repository_dest = item["image"].format(endpoint)
        image = docker_client.images.pull(repository_src, item["tag"])
        image.tag(repository_dest, item["tag"])
        docker_client.images.push(repository_dest, item["tag"])
        docker_client.images.remove(image=f"{repository_src}:{item['tag']}")
        docker_client.images.remove(image=f"{repository_dest}:{item['tag']}")

    return endpoint
