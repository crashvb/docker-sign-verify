#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import pytest

from docker_sign_verify import RegistryV2Manifest, RegistryV2ManifestList

from .testutils import get_test_data


@pytest.fixture
def manifest_list_registry(request) -> bytes:
    """Provides a sample registry manifest list."""
    return get_test_data(request, __name__, "manifest_list_registry.json")


@pytest.fixture
def registry_v2_manifest_list(manifest_list_registry: bytes) -> RegistryV2ManifestList:
    """Provides a RegistryV2ManifestList instance for the sample registry manifest list."""
    # Do not use caching; get a new instance for each test
    return RegistryV2ManifestList(manifest_list_registry)


def test___init__(registry_v2_manifest_list: RegistryV2ManifestList):
    """Test that an RegistryV2ManifestList can be instantiated."""
    assert registry_v2_manifest_list


def test___bytes__(
    registry_v2_manifest_list: RegistryV2ManifestList, manifest_list_registry: bytes
):
    """Test __str__ pass-through for different variants."""
    assert bytes(registry_v2_manifest_list) == manifest_list_registry


def test___str__(
    registry_v2_manifest_list: RegistryV2ManifestList, manifest_list_registry: bytes
):
    """Test __str__ pass-through for different variants."""
    assert str(registry_v2_manifest_list) == manifest_list_registry.decode("utf-8")


def test_get_manifests(registry_v2_manifest_list: RegistryV2ManifestList):
    """Test manifest list retrieval."""
    manifests = [
        "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
        "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
    ]
    assert registry_v2_manifest_list.get_manifests() == manifests
    assert (
        registry_v2_manifest_list.get_manifests(architecture="ppc64le") == manifests[:1]
    )
    assert registry_v2_manifest_list.get_manifests(os="linux") == manifests


def test_cast_from_manifest(manifest_list_registry: bytes):
    """Test down-casting."""
    registry_v2_manifest = RegistryV2Manifest(manifest_list_registry)

    manifest_list = RegistryV2ManifestList.from_manifest(registry_v2_manifest)
    assert len(manifest_list.get_manifests()) == 2
