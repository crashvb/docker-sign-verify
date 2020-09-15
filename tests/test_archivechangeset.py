#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import ArchiveChangeset, ArchiveManifest

from .testutils import get_test_data


@pytest.fixture
def archive_changeset(archive_changeset_raw: bytes) -> ArchiveChangeset:
    """Provides an ArchiveChangeset instance for the sample archive manifest."""
    # Do not use caching; get a new instance for each test
    return ArchiveChangeset(archive_changeset_raw)


@pytest.fixture
def archive_changeset_raw(request) -> bytes:
    """Provides a sample archive manifest."""
    return get_test_data(request, __name__, "archive_changeset.json")


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


def test___init__(archive_changeset: ArchiveChangeset):
    """Test that an ArchiveChangeset can be instantiated."""
    assert archive_changeset


def test___bytes__(archive_changeset: ArchiveChangeset, archive_changeset_raw: bytes):
    """Test __str__ pass-through for different variants."""
    assert bytes(archive_changeset) == archive_changeset_raw


def test___str__(archive_changeset: ArchiveChangeset, archive_changeset_raw: bytes):
    """Test __str__ pass-through for different variants."""
    assert str(archive_changeset) == archive_changeset_raw.decode("utf-8")


# def test_get_repository_tag(image_name: ImageName):
#     """Test retrieving a repository tag from an image name."""
#     # TODO


@pytest.mark.parametrize(
    "expected,tag",
    [
        ("image:tag1", "image:tag1"),
        ("tag2", "tag2"),
        ("image:tag3", "library/image:tag3"),
        ("tag4", "library/tag4"),
    ],
)
def test_normalize_tags(expected: str, tag: str):
    """Test repository tag normalization."""
    assert ArchiveChangeset.normalize_tags([tag]) == [expected]


@pytest.mark.parametrize("tags", [["iamge:tag1"], None])
def test_append_manifest(
    archive_changeset: ArchiveChangeset,
    formattedsha256: FormattedSHA256,
    tags,
):
    """Test appending manifests."""
    assert len(archive_changeset.get_manifests()) == 2

    # Append a new manifest ...
    manifest = ArchiveManifest(b"{}")
    manifest.set_config_digest(formattedsha256)
    manifest.set_tags(tags)
    archive_changeset.append_manifest(manifest)
    assert len(archive_changeset.get_manifests()) == 3

    # Append it again ...
    archive_changeset.append_manifest(manifest)
    assert len(archive_changeset.get_manifests()) == 3

    # TODO: Test more digest / tag combinations to ensure that tags are properly moved, deleted, assigned, etc ...


def test_get_manifest(archive_changeset: ArchiveChangeset, image_name: ImageName):
    """Test manifest retrieval."""
    manifest = archive_changeset.get_manifest(image_name)
    if image_name.resolve_digest():
        assert manifest.get_config_digest() == image_name.resolve_digest()
    if image_name.tag:
        assert ArchiveChangeset.get_repository_tag(image_name) in manifest.get_tags()


def test_get_manifests(archive_changeset: ArchiveChangeset):
    """Test retrieving all manifests."""
    assert len(archive_changeset.get_manifests()) == 2


def test_remove_manifest(archive_changeset: ArchiveChangeset, image_name: ImageName):
    """Test manifest removal."""
    assert len(archive_changeset.get_manifests()) == 2
    archive_changeset.remove_manifest(image_name.resolve_digest())
    assert len(archive_changeset.get_manifests()) == 1


def test_remove_tags(archive_changeset: ArchiveChangeset):
    """Test repository tag removal"""
    image_name = ImageName(
        "base",
        digest=FormattedSHA256(
            "adecf4209bb9dd67d96393774cbd7f8bd2bad3596da42cde33daa0c41b14ac62"
        ),
        tag="7.2",
    )
    tag = ArchiveChangeset.get_repository_tag(image_name)
    manifest = archive_changeset.get_manifest(image_name)
    assert tag in manifest.get_tags()

    archive_changeset.remove_tags(["dummy"])
    manifest = archive_changeset.get_manifest(image_name)
    assert tag in manifest.get_tags()

    archive_changeset.remove_tags([tag])
    manifest = archive_changeset.get_manifest(image_name)
    assert not manifest.get_tags()
