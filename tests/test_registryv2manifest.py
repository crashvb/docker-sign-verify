#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName

from docker_sign_verify import RegistryV2Manifest

from .testutils import get_test_data


@pytest.fixture()
def formattedsha256() -> FormattedSHA256:
    """Provides a FormattedSHA256 instance with a distinct digest value."""
    return FormattedSHA256(
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
    )


@pytest.fixture
def manifest_registry(request) -> bytes:
    """Provides a sample registry manifest."""
    return get_test_data(request, __name__, "manifest_registry.json")


@pytest.fixture
def registry_v2_manifest(manifest_registry: bytes) -> RegistryV2Manifest:
    """Provides a RegistryV2Manifest instance for the sample registry manifest."""
    # Do not use caching; get a new instance for each test
    return RegistryV2Manifest(manifest_registry)


def test___init__(registry_v2_manifest: RegistryV2Manifest):
    """Test that an RegistryV2Manifest can be instantiated."""
    assert registry_v2_manifest


def test___bytes__(registry_v2_manifest: RegistryV2Manifest, manifest_registry: bytes):
    """Test __str__ pass-through for different variants."""
    assert bytes(registry_v2_manifest) == manifest_registry


def test___str__(registry_v2_manifest: RegistryV2Manifest, manifest_registry: bytes):
    """Test __str__ pass-through for different variants."""
    assert str(registry_v2_manifest) == manifest_registry.decode("utf-8")


def test_set_config_digest(
    registry_v2_manifest: RegistryV2Manifest, formattedsha256: FormattedSHA256
):
    """Test overriding manifest values."""
    size = 1234
    registry_v2_manifest.set_config_digest(formattedsha256, size)
    assert registry_v2_manifest.get_config_digest() == formattedsha256
    assert registry_v2_manifest.get_json()["config"]["size"] == size


# TODO: def test_set_layers(registry_v2_manifest: RegistryV2Manifest)


def test_get_config_digest(registry_v2_manifest: RegistryV2Manifest):
    """Test image configuration digest retrieval."""
    formattedsha256 = FormattedSHA256(
        "8f1196ff19e7b5c5861de192ae77e8d7a692fcbca2dd3174d324980f72ab49bf"
    )
    assert registry_v2_manifest.get_config_digest() == formattedsha256
    assert (
        registry_v2_manifest.get_config_digest(ImageName.parse("ignored"))
        == formattedsha256
    )


def test_get_layers(registry_v2_manifest: RegistryV2Manifest):
    """Test manifest layer retrieval."""
    layers = [
        "sha256:6c8c72249e560701aa1da4cd40192274a8c0419ddb8e4a553aa02b5a1acdb863",
        "sha256:1403b179e2c9df4f57e9ea94e32882739c6b3d75ed756d4e67fcc424288c29cc",
    ]
    assert registry_v2_manifest.get_layers() == layers
    assert registry_v2_manifest.get_layers(ImageName.parse("ignored")) == layers
