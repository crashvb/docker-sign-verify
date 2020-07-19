#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import pytest
from docker_registry_client_async import FormattedSHA256, ImageName

from docker_sign_verify import DeviceMapperRepositoryManifest
from .testutils import get_test_data


@pytest.fixture
def devicemapper_repository_manifest(
    manifest_repository: bytes,
) -> DeviceMapperRepositoryManifest:
    """Provides a DeviceMapperRepositoryManifest instance for the sample repository manifest."""
    # Do not use caching; get a new instance for each test
    return DeviceMapperRepositoryManifest(manifest_repository)


@pytest.fixture()
def formattedsha256() -> FormattedSHA256:
    """Provides a FormattedSHA256 instance with a distinct digest value."""
    return FormattedSHA256(
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
    )


@pytest.fixture
def manifest_repository(request) -> bytes:
    """Provides a sample repository manifest."""
    return get_test_data(request, __name__, "manifest_repository.json")


def test___init__(devicemapper_repository_manifest: DeviceMapperRepositoryManifest):
    """Test that an DeviceMapperRepositoryManifest can be instantiated."""
    assert devicemapper_repository_manifest


def test___bytes__(
    devicemapper_repository_manifest: DeviceMapperRepositoryManifest,
    manifest_repository: bytes,
):
    """Test __str__ pass-through for different variants."""
    assert bytes(devicemapper_repository_manifest) == manifest_repository


def test___str__(
    devicemapper_repository_manifest: DeviceMapperRepositoryManifest,
    manifest_repository: bytes,
):
    """Test __str__ pass-through for different variants."""
    assert str(devicemapper_repository_manifest) == manifest_repository.decode("utf-8")


# TODO: def test__get_repository_key
# TODO: get_combined_layerid


@pytest.mark.parametrize(
    "img_name", ["endpoint:port/namespace/image:tag", "rancher/swarmkit:v1.13.0-beta.1"]
)
def test_override_config(
    devicemapper_repository_manifest: DeviceMapperRepositoryManifest,
    formattedsha256: FormattedSHA256,
    img_name: str,
):
    """Test overriding manifest values."""
    image_name = ImageName.parse(img_name)
    devicemapper_repository_manifest.override_config(formattedsha256, image_name)
    assert (
        devicemapper_repository_manifest.get_config_digest(image_name)
        == formattedsha256
    )


@pytest.mark.parametrize(
    "img_name,config_digest",
    [
        (
            "busybox:latest",
            "sha256:6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30",
        )
    ],
)
def test_get_config_digest(
    devicemapper_repository_manifest: DeviceMapperRepositoryManifest,
    img_name: str,
    config_digest: str,
):
    """Test image configuration digest retrieval."""
    image_name = ImageName.parse(img_name)
    assert (
        devicemapper_repository_manifest.get_config_digest(image_name) == config_digest
    )


# def test_repository_get_layers(devicemapper_repository_manifest: DeviceMapperRepositoryManifest):
#    """Test manifest layer retrieval."""
#    with pytest.raises(NotImplementedError):
#        devicemapper_repository_manifest.get_layers()
