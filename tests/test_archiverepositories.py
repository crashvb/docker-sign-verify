#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import ArchiveRepositories

from .testutils import get_test_data


@pytest.fixture
def archive_repositories(archive_repositories_raw: bytes) -> ArchiveRepositories:
    """Provides an ArchiveRepositories instance for the sample archive manifest."""
    # Do not use caching; get a new instance for each test
    return ArchiveRepositories(archive_repositories_raw)


@pytest.fixture
def archive_repositories_raw(request) -> bytes:
    """Provides a sample archive manifest."""
    return get_test_data(request, __name__, "archive_repositories.json")


@pytest.fixture(
    params=[
        "busybox:1.30.1@sha256:a57c26390d4b78fd575fac72ed31f16a7a2fa3ebdccae4598513e8964dace9b2"
    ]
)
def image_name(request) -> ImageName:
    """Provides a 'known good' image name."""
    yield ImageName.parse(request.param)


def test___init__(archive_repositories: ArchiveRepositories):
    """Test that an ArchiveRepositories can be instantiated."""
    assert archive_repositories


def test___bytes__(
    archive_repositories: ArchiveRepositories, archive_repositories_raw: bytes
):
    """Test __str__ pass-through for different variants."""
    assert bytes(archive_repositories) == archive_repositories_raw


def test___str__(
    archive_repositories: ArchiveRepositories, archive_repositories_raw: bytes
):
    """Test __str__ pass-through for different variants."""
    assert str(archive_repositories) == archive_repositories_raw.decode("utf-8")


def test_get_tag(archive_repositories: ArchiveRepositories, image_name: ImageName):
    """Test repository tag retrieval."""
    tag = archive_repositories.get_tag(image_name)
    assert tag
    assert FormattedSHA256(tag) == image_name.digest
    assert not archive_repositories.get_tag(ImageName("does_not_exist"))
    assert not archive_repositories.get_tag(ImageName("does_not", tag="exist"))


@pytest.mark.parametrize(
    "name", ["image1", "image2:tag2", "library/image3", "library/image4:tag4"]
)
def test_set_tag(
    archive_repositories: ArchiveRepositories, image_name: ImageName, name: str
):
    """Test repository tag assignment."""
    tag = archive_repositories.get_tag(image_name)
    assert tag
    assert FormattedSHA256(tag) == image_name.digest

    digest = FormattedSHA256.calculate(name.encode("utf-8"))
    name = ImageName.parse(name)
    archive_repositories.set_tag(name, digest)
    assert FormattedSHA256(archive_repositories.get_tag(name)) == digest
