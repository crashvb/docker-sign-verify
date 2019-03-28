#!/usr/bin/env python

"""Manifest tests."""

import json
import pytest

from docker_sign_verify import (
    ArchiveManifest,
    DeviceMapperRepositoryManifest,
    FormattedSHA256,
    ImageName,
    RegistryV2Manifest,
)

from .testutils import get_test_data


@pytest.fixture()
def formattedsha256():
    return FormattedSHA256(
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
    )


@pytest.fixture()
def sha256_archive_layer(formattedsha256: FormattedSHA256):
    return "{0}/layer.tar".format(formattedsha256.sha256)


@pytest.fixture
def manifest_archive(request):
    return get_test_data(request, __name__, "manifest_archive.json")


@pytest.fixture
def manifest_registry(request):
    return get_test_data(request, __name__, "manifest_registry.json")


@pytest.fixture
def manifest_repository(request):
    return get_test_data(request, __name__, "manifest_repository.json")


@pytest.fixture
def archive_manifest(manifest_archive):
    # Do not use caching; get a new instance for each test
    return ArchiveManifest(manifest_archive)


@pytest.fixture
def devicemapper_repository_manifest(manifest_repository):
    # Do not use caching; get a new instance for each test
    return DeviceMapperRepositoryManifest(manifest_repository)


@pytest.fixture
def registry_v2_manifest(manifest_registry):
    # Do not use caching; get a new instance for each test
    return RegistryV2Manifest(manifest_registry)


def test_init(
    archive_manifest: ArchiveManifest,
    devicemapper_repository_manifest: DeviceMapperRepositoryManifest,
    registry_v2_manifest: RegistryV2Manifest,
):
    """Test that all manifest types can be instantiated."""
    assert archive_manifest
    assert devicemapper_repository_manifest
    assert registry_v2_manifest


def test_str(
    archive_manifest: ArchiveManifest,
    devicemapper_repository_manifest: DeviceMapperRepositoryManifest,
    registry_v2_manifest: RegistryV2Manifest,
    manifest_archive: bytes,
    manifest_registry: bytes,
    manifest_repository: bytes,
):
    """Test __str__ pass-through for all manifest types (with encoding)."""

    # Note: Due to whitespace differences, compare the parsed string form.
    assert json.loads(str(archive_manifest)) == json.loads(manifest_archive)
    assert json.loads(str(devicemapper_repository_manifest)) == json.loads(
        manifest_repository
    )
    assert json.loads(str(registry_v2_manifest)) == json.loads(manifest_registry)


def test_archive__layer_to_hash(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
):
    """Test layer to hash conversion."""
    assert archive_manifest.layer_to_digest(sha256_archive_layer) == formattedsha256


def test_archive__hash_to_layer(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
):
    """Test hash to layer conversion."""
    assert archive_manifest.digest_to_layer(formattedsha256) == sha256_archive_layer


@pytest.mark.parametrize(
    "img_name,config_value",
    [
        (
            "a51f3f9281a1a3d89dce25fec8acffbe9f59ddb67d98e04245c4c886e32d3782",
            "a51f3f9281a1a3d89dce25fec8acffbe9f59ddb67d98e04245c4c886e32d3782.json",
        ),
        (
            "base:7.2",
            "adecf4209bb9dd67d96393774cbd7f8bd2bad3596da42cde33daa0c41b14ac62.json",
        ),
        (
            "adecf4209bb9dd67d96393774cbd7f8bd2bad3596da42cde33daa0c41b14ac62",
            "adecf4209bb9dd67d96393774cbd7f8bd2bad3596da42cde33daa0c41b14ac62.json",
        ),
    ],
)
def test_archive__get_config(
    archive_manifest: ArchiveManifest, img_name: str, config_value: str
):
    """Test configuration retrieval."""
    image_name = ImageName.parse(img_name)
    assert archive_manifest.get_config(image_name)["Config"] == config_value


@pytest.mark.parametrize("repotag", ["REPOTAG", None])
def test_archive_append_config(
    archive_manifest: ArchiveManifest,
    sha256_archive_layer: str,
    formattedsha256: FormattedSHA256,
    repotag,
):
    """Test appending configurations."""
    layers = [formattedsha256]
    archive_manifest.append_config(formattedsha256, layers, repotag)
    image_name = ImageName(None, formattedsha256.sha256)
    config = archive_manifest.get_config(image_name)
    assert config["Config"] == "{0}.json".format(formattedsha256.sha256)
    assert config["Layers"] == [sha256_archive_layer]
    assert config.get("RepoTags", None) == repotag


def test_archive_get_config_digest(archive_manifest: ArchiveManifest):
    """Test configuration digest retrieval."""
    formattedsha256 = FormattedSHA256(
        "a51f3f9281a1a3d89dce25fec8acffbe9f59ddb67d98e04245c4c886e32d3782"
    )
    image_name = ImageName.parse(formattedsha256.sha256)
    assert archive_manifest.get_config_digest(image_name) == formattedsha256


def test_archive_get_layers(archive_manifest: ArchiveManifest):
    """Test manifest layer retrieval."""
    sha256 = "a51f3f9281a1a3d89dce25fec8acffbe9f59ddb67d98e04245c4c886e32d3782"
    image_name = ImageName.parse(sha256)
    assert archive_manifest.get_layers(image_name) == [
        "sha256:137120c8596a15ab42c39c0c5cf83ef864b6b65b5516887c895915e87292bd07",
        "sha256:755520f73bc74ae73b12f53229e401e8d4c584b74f5704d2d36ba7c45e2657cf",
        "sha256:13fb089903a5e0e9b00d78ba48496da528ce8d81e08a1042ebeced8c35d714cb",
        "sha256:f86d68f70ca006025a7f7013f69898f78d1d9272c4d3909e3ec4c7f9958da20e",
        "sha256:7b4a4edd704242cec1710679a088be8aabff25c3a79f4eecbe8d11d57c53a20b",
        "sha256:ef4724d42630f3022ef67c3f6749e85a13e81b8efcf98fbd517476499f10e5ab",
    ]


def test_registry_override_config(
    registry_v2_manifest: RegistryV2Manifest, formattedsha256: FormattedSHA256
):
    """Test overriding manifest values."""
    size = 1234
    registry_v2_manifest.set_config_digest(formattedsha256, size)
    assert registry_v2_manifest.get_config_digest() == formattedsha256
    assert registry_v2_manifest.json["config"]["size"] == size


def test_registry_get_config_digest(registry_v2_manifest: RegistryV2Manifest):
    formattedsha256 = FormattedSHA256(
        "8f1196ff19e7b5c5861de192ae77e8d7a692fcbca2dd3174d324980f72ab49bf"
    )
    assert registry_v2_manifest.get_config_digest() == formattedsha256
    assert (
        registry_v2_manifest.get_config_digest(ImageName.parse("ignored"))
        == formattedsha256
    )


def test_registry_get_layers(registry_v2_manifest: RegistryV2Manifest):
    """Test manifest layer retrieval."""
    layers = [
        "sha256:6c8c72249e560701aa1da4cd40192274a8c0419ddb8e4a553aa02b5a1acdb863",
        "sha256:1403b179e2c9df4f57e9ea94e32882739c6b3d75ed756d4e67fcc424288c29cc",
    ]
    assert registry_v2_manifest.get_layers() == layers
    assert registry_v2_manifest.get_layers(ImageName.parse("ignored")) == layers


@pytest.mark.parametrize(
    "img_name", ["endpoint:port/namespace/image:tag", "rancher/swarmkit:v1.13.0-beta.1"]
)
def test_repository_override_config(
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
def test_repository_get_config_digest(
    devicemapper_repository_manifest: DeviceMapperRepositoryManifest,
    img_name: str,
    config_digest: str,
):
    image_name = ImageName.parse(img_name)
    assert (
        devicemapper_repository_manifest.get_config_digest(image_name) == config_digest
    )


# def test_repository_get_layers(devicemapper_repository_manifest: DeviceMapperRepositoryManifest):
#    """Test manifest layer retrieval."""
#    with pytest.raises(NotImplementedError):
#        devicemapper_repository_manifest.get_layers()
