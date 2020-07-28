#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import ArchiveManifest

from .testutils import get_test_data


@pytest.fixture
def archive_manifest(manifest_archive: bytes) -> ArchiveManifest:
    """Provides an ArchiveManifest instance for the sample archive manifest."""
    # Do not use caching; get a new instance for each test
    return ArchiveManifest(manifest_archive)


@pytest.fixture()
def formattedsha256() -> FormattedSHA256:
    """Provides a FormattedSHA256 instance with a distinct digest value."""
    return FormattedSHA256(
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
    )


@pytest.fixture(
    params=[
        "ignored@sha256:a51f3f9281a1a3d89dce25fec8acffbe9f59ddb67d98e04245c4c886e32d3782",
        "base:7.2@sha256:adecf4209bb9dd67d96393774cbd7f8bd2bad3596da42cde33daa0c41b14ac62",
        "ignored@sha256:adecf4209bb9dd67d96393774cbd7f8bd2bad3596da42cde33daa0c41b14ac62",
    ]
)
def image_name(request) -> ImageName:
    """Provides a 'known good' image name."""
    yield ImageName.parse(request.param)


@pytest.fixture
def manifest_archive(request) -> bytes:
    """Provides a sample archive manifest."""
    return get_test_data(request, __name__, "manifest_archive.json")


@pytest.fixture()
def sha256_archive_layer(formattedsha256: FormattedSHA256) -> str:
    """Provides the archive layer identifier for the distinct digest value."""
    return "{0}/layer.tar".format(formattedsha256.sha256)


def test___init__(archive_manifest: ArchiveManifest):
    """Test that an ArchiveManifest can be instantiated."""
    assert archive_manifest


def test___bytes__(archive_manifest: ArchiveManifest, manifest_archive: bytes):
    """Test __str__ pass-through for different variants."""
    assert bytes(archive_manifest) == manifest_archive


def test___str__(archive_manifest: ArchiveManifest, manifest_archive: bytes):
    """Test __str__ pass-through for different variants."""
    assert str(archive_manifest) == manifest_archive.decode("utf-8")


def test___layer_to_digest(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
):
    """Test layer to hash conversion."""
    assert archive_manifest.layer_to_digest(sha256_archive_layer) == formattedsha256


def test__digest_to_layer(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
):
    """Test hash to layer conversion."""
    assert archive_manifest.digest_to_layer(formattedsha256) == sha256_archive_layer


def test_get_config(archive_manifest: ArchiveManifest, image_name: ImageName):
    """Test configuration retrieval."""
    assert (
        archive_manifest.get_config(image_name)["Config"]
        == f"{image_name.resolve_digest().sha256}.json"
    )


@pytest.mark.parametrize("repotag", ["REPOTAG", None])
def test_append_config(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
    repotag,
):
    """Test appending configurations."""
    layers = [formattedsha256]
    archive_manifest.append_config(formattedsha256, layers, repotag)
    image_name = ImageName("ignored", digest=formattedsha256)
    config = archive_manifest.get_config(image_name)
    assert config["Config"] == "{0}.json".format(formattedsha256.sha256)
    assert config["Layers"] == [sha256_archive_layer]
    assert config.get("RepoTags", None) == repotag


def test_get_config_digest(archive_manifest: ArchiveManifest, image_name: ImageName):
    """Test configuration digest retrieval."""
    assert archive_manifest.get_config_digest(image_name) == image_name.resolve_digest()


def test_get_layers(archive_manifest: ArchiveManifest, image_name: ImageName):
    """Test manifest layer retrieval."""
    if (
        image_name.resolve_digest()
        == "sha256:a51f3f9281a1a3d89dce25fec8acffbe9f59ddb67d98e04245c4c886e32d3782"
    ):
        assert archive_manifest.get_layers(image_name) == [
            "sha256:137120c8596a15ab42c39c0c5cf83ef864b6b65b5516887c895915e87292bd07",
            "sha256:755520f73bc74ae73b12f53229e401e8d4c584b74f5704d2d36ba7c45e2657cf",
            "sha256:13fb089903a5e0e9b00d78ba48496da528ce8d81e08a1042ebeced8c35d714cb",
            "sha256:f86d68f70ca006025a7f7013f69898f78d1d9272c4d3909e3ec4c7f9958da20e",
            "sha256:7b4a4edd704242cec1710679a088be8aabff25c3a79f4eecbe8d11d57c53a20b",
            "sha256:ef4724d42630f3022ef67c3f6749e85a13e81b8efcf98fbd517476499f10e5ab",
        ]
    else:
        assert archive_manifest.get_layers(image_name) == [
            "sha256:2c2e149ae9a88ae6bee1583459b2d3e5e317877b795c08781fab36eab4b4329f",
            "sha256:83419ef1d0ad0520c9fc44da4345637e5c05e34fa564ddf2fb6d6f94a6b2d205",
            "sha256:c2d494c64683fb7edac60aaffc570c514c1c80c797aafcf25b8a9438690da4df",
            "sha256:d3b1a8ce509767258045f6cc050dfc8cff27f66f9fa8c61c9dc46733e492e0af",
            "sha256:0a0084e273d71f3b39100a5c209a3208fafdb90e3dd038cded5e2a54265d23fa",
        ]
