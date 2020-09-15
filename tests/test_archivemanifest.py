#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import json

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import ArchiveManifest

from .testutils import get_test_data


@pytest.fixture
def archive_manifest(archive_manifest_raw) -> ArchiveManifest:
    """Provides an ArchiveManifest instance for the sample archive manifest."""
    # Do not use caching; get a new instance for each test
    return ArchiveManifest(archive_manifest_raw)


@pytest.fixture
def archive_manifest_raw(request) -> bytes:
    """Provides a sample archive manifest."""
    return get_test_data(request, __name__, "manifest_archive.json")


@pytest.fixture()
def formattedsha256() -> FormattedSHA256:
    """Provides a FormattedSHA256 instance with a distinct digest value."""
    return FormattedSHA256(
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
    )


@pytest.fixture()
def image_name() -> ImageName:
    """Provides a 'known good' image name."""
    yield ImageName.parse(
        "ignored@sha256:a51f3f9281a1a3d89dce25fec8acffbe9f59ddb67d98e04245c4c886e32d3782"
    )


@pytest.fixture()
def sha256_archive_layer(formattedsha256: FormattedSHA256) -> str:
    """Provides the archive layer identifier for the distinct digest value."""
    return f"{formattedsha256.sha256}/layer.tar"


def test___init__(archive_manifest: ArchiveManifest):
    """Test that an ArchiveManifest can be instantiated."""
    assert archive_manifest


def test___bytes__(archive_manifest: ArchiveManifest, archive_manifest_raw):
    """Test __str__ pass-through for different variants."""
    assert bytes(archive_manifest) == archive_manifest_raw


def test___str__(archive_manifest: ArchiveManifest, archive_manifest_raw):
    """Test __str__ pass-through for different variants."""
    assert str(archive_manifest) == archive_manifest_raw.decode("utf-8")


def test_digest_to_layer(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
):
    """Test hash to layer conversion."""
    assert archive_manifest.digest_to_layer(formattedsha256) == sha256_archive_layer


def test_from_json():
    """Test and an ArchiveManifest can be initialized from JSON."""
    _json = json.loads('{"x":"1"}')
    archive_manifest = ArchiveManifest.from_json(_json)
    assert archive_manifest.get_json() == _json


def test_layer_to_digest(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
):
    """Test layer to hash conversion."""
    assert archive_manifest.layer_to_digest(sha256_archive_layer) == formattedsha256


def test_get_set_tags(archive_manifest: ArchiveManifest):
    """Test repository tag retrieval and assignment."""
    assert not archive_manifest.get_tags()
    tags = {"1", "2", "3"}
    archive_manifest.set_tags(tags)
    assert archive_manifest.get_tags() == tags
    archive_manifest.set_tags({"4", "5", "6"})
    assert archive_manifest.get_tags() != tags


def test_remove_tags(archive_manifest: ArchiveManifest):
    """Test repository tag removal."""
    assert not archive_manifest.get_tags()
    tags = {"11", "22", "33"}
    archive_manifest.set_tags(tags)
    assert archive_manifest.get_tags() == tags
    archive_manifest.remove_tags({"22"})
    assert archive_manifest.get_tags() == {"11", "33"}


def test_set_config_digest(
    archive_manifest: ArchiveManifest,
    formattedsha256: FormattedSHA256,
    image_name: ImageName,
):
    """Test configuration digest assignment."""
    assert archive_manifest.get_config_digest() == image_name.digest
    archive_manifest.set_config_digest(formattedsha256)
    assert archive_manifest.get_config_digest() == formattedsha256


def test_set_layers(
    archive_manifest: ArchiveManifest, formattedsha256: FormattedSHA256
):
    """Test manifest layer assignment."""
    archive_manifest.set_layers([formattedsha256])
    assert archive_manifest.get_layers() == [formattedsha256]


def test_get_config_digest(archive_manifest: ArchiveManifest, image_name: ImageName):
    """Test configuration digest retrieval."""
    assert archive_manifest.get_config_digest(image_name) == image_name.resolve_digest()


def test_get_layers(archive_manifest: ArchiveManifest):
    """Test manifest layer retrieval."""
    assert archive_manifest.get_layers() == [
        "sha256:137120c8596a15ab42c39c0c5cf83ef864b6b65b5516887c895915e87292bd07",
        "sha256:755520f73bc74ae73b12f53229e401e8d4c584b74f5704d2d36ba7c45e2657cf",
        "sha256:13fb089903a5e0e9b00d78ba48496da528ce8d81e08a1042ebeced8c35d714cb",
        "sha256:f86d68f70ca006025a7f7013f69898f78d1d9272c4d3909e3ec4c7f9958da20e",
        "sha256:7b4a4edd704242cec1710679a088be8aabff25c3a79f4eecbe8d11d57c53a20b",
        "sha256:ef4724d42630f3022ef67c3f6749e85a13e81b8efcf98fbd517476499f10e5ab",
    ]
