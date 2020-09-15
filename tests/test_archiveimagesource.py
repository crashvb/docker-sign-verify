#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name

"""ArchiveImageSource tests."""

import logging

from datetime import datetime
from pathlib import Path
from shutil import copy
from typing import Dict

import aiofiles
import pytest

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import (
    ArchiveImageSource,
    ArchiveManifest,
    ImageConfig,
    SignatureTypes,
)
from docker_sign_verify.aiotempfile import open as aiotempfile
from docker_sign_verify.imagesource import (
    ImageSourceSignImage,
    ImageSourceVerifyImageIntegrity,
)

from .conftest import get_test_data_archive, TypingKnownGoodImage
from .stubs import FakeSigner
from .test_archivemanifest import archive_manifest_raw  # Needed
from .testutils import get_test_data_path

LOGGER = logging.getLogger(__name__)

pytestmark = [pytest.mark.asyncio]


class TypingKnownGoodImageArchive(TypingKnownGoodImage):
    # pylint: disable=missing-class-docstring
    archive_image_source: ArchiveImageSource
    _digests: Dict[str, FormattedSHA256]


@pytest.fixture(params=get_test_data_archive())
def known_good_image_archive(request, tmp_path: Path) -> TypingKnownGoodImageArchive:
    """Provides 'known good' metadata for a local image that can be modified."""
    path_destination = tmp_path.joinpath(request.param["resource"])
    path_source = get_test_data_path(request, request.param["resource"])
    copy(str(path_source), str(path_destination))

    request.param["archive_image_source"] = ArchiveImageSource(archive=path_destination)
    request.param["image_name"] = ImageName(request.param["image"])
    if "digest" in request.param:
        request.param["image_name"].digest = request.param["digest"] = FormattedSHA256(
            request.param["digest"]
        )
    if "tag" in request.param:
        request.param["image_name"].tag = request.param["tag"]

    for key, value in request.param["_digests"].items():
        request.param["_digests"][key] = FormattedSHA256(value)

    return request.param


def test___init__(known_good_image_archive: TypingKnownGoodImageArchive):
    """Test that the image source can be instantiated."""
    assert known_good_image_archive["archive_image_source"]


async def test_get_image_config(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test image configuration retrieval."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    LOGGER.debug("Retrieving image configuration for: %s ...", image_name)
    image_config = await archive_image_source.get_image_config(image_name, **kwargs)
    assert isinstance(image_config, ImageConfig)


async def test_get_image_layer_to_disk(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test layer retrieval to disk."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    manifest = await archive_image_source.get_manifest(image_name, **kwargs)
    for layer in manifest.get_layers(image_name):
        LOGGER.debug("Retrieving blob: %s/%s ...", image_name, layer)
        async with aiotempfile(mode="w+b") as file:
            result = await archive_image_source.get_image_layer_to_disk(
                image_name, layer, file, **kwargs
            )
            LOGGER.debug("Verifying digest of written file ...")
        # TODO: What is the correct digest value?
        # assert result["digest"] == layer


async def test_get_manifest(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test manifest retrieval."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    manifest = await archive_image_source.get_manifest(image_name, **kwargs)
    assert isinstance(manifest, ArchiveManifest)
    if image_name.resolve_digest():
        assert (
            manifest.get_digest()
            == known_good_image_archive["_digests"][
                f"manifest_{image_name.digest.sha256}"
            ]
        )
    if image_name.tag:
        assert (
            manifest.get_digest()
            == known_good_image_archive["_digests"][f"manifest_{image_name.tag}"]
        )


async def test_layer_exists(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test layer existence."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    manifest = await archive_image_source.get_manifest(image_name, **kwargs)
    layer = manifest.get_layers(image_name)[-1]
    assert await archive_image_source.layer_exists(image_name, layer, **kwargs)
    assert not await archive_image_source.layer_exists(
        image_name, FormattedSHA256("0" * 64), **kwargs
    )


async def test_put_image(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test image layer assignment."""
    archive_image_source_src = known_good_image_archive["archive_image_source"]
    archive_image_source_dest = ArchiveImageSource(
        archive=Path(archive_image_source_src.archive.parent, f"{__name__}.tar")
    )
    image_name = known_good_image_archive["image_name"]

    LOGGER.debug(
        "Retrieving image from %s: %s ...", archive_image_source_src.archive, image_name
    )
    response = await archive_image_source_src.verify_image_integrity(
        image_name, **kwargs
    )

    if image_name.tag:
        image_name.tag += __name__

    LOGGER.debug(
        "Storing image to %s: %s ...", archive_image_source_dest.archive, image_name
    )
    await archive_image_source_dest.put_image(
        archive_image_source_src,
        image_name,
        response["manifest"],
        response["image_config"],
        response["uncompressed_layer_files"],
        **kwargs,
    )

    LOGGER.debug("Retrieving image configuration for: %s ...", image_name)
    tmp = await archive_image_source_dest.get_image_config(image_name, **kwargs)
    assert tmp.get_digest() == response["image_config"].get_digest()

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    manifest = await archive_image_source_dest.get_manifest(image_name, **kwargs)
    for layer in manifest.get_layers(image_name):
        LOGGER.debug("Retrieving blob: %s/%s ...", image_name, layer)
        async with aiotempfile(mode="w+b") as file:
            result = await archive_image_source_dest.get_image_layer_to_disk(
                image_name, layer, file, **kwargs
            )
            LOGGER.debug("Verifying digest of written file ...")
        # TODO: What is the correct digest value?


async def test_put_image_config(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test image configuration assignment."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    LOGGER.debug("Retrieving image configuration for: %s ...", image_name)
    image_config = await archive_image_source.get_image_config(image_name, **kwargs)

    # Modify the configuration
    image_config_modified = image_config.clone()
    json = image_config_modified.get_json()
    labels = image_config_modified._get_labels(json)
    labels["foo"] = datetime.now().strftime("%d%m%Y%H%M%S")
    image_config_modified._set_json(json)

    image_name_modified = image_name.clone()
    if image_name_modified.digest:
        image_name_modified.digest = image_config_modified.get_digest()

    LOGGER.debug(
        "Storing modified image configuration: %s ...",
        image_config_modified.get_digest(),
    )
    await archive_image_source.put_image_config(
        image_name_modified, image_config_modified, **kwargs
    )
    assert await archive_image_source._file_exists(
        f"{image_config_modified.get_digest().sha256}.json"
    )


async def test_put_image_layer(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test image layer assignment."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    content = b"This is sample content"

    LOGGER.debug("Storing layer ...")
    response = await archive_image_source.put_image_layer(image_name, content, **kwargs)
    # TODO: How do we validate the randomly generate digest as a return value?
    # assert response == FormattedSHA256.calculate(content)


async def test_put_image_layer_from_disk(
    known_good_image_archive: TypingKnownGoodImageArchive, tmp_path: Path, **kwargs
):
    """Test image layer assignment from disk."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    content = b"This is sample content"

    LOGGER.debug("Writing layer to disk ...")
    path = tmp_path.joinpath("layer.txt")
    async with aiofiles.open(path, mode="w+b") as file:
        await file.write(content)

    LOGGER.debug("Storing layer from disk: %s ...", path)
    async with aiofiles.open(path, mode="r+b") as file:
        response = await archive_image_source.put_image_layer_from_disk(
            image_name, file, **kwargs
        )
    # TODO: How do we validate the randomly generate digest as a return value?
    # assert response == FormattedSHA256.calculate(content)


async def test_put_manifest(
    known_good_image_archive: TypingKnownGoodImageArchive,
    archive_manifest_raw,
    **kwargs,
):
    """Test manifest assignment."""
    archive_image_source = known_good_image_archive["archive_image_source"]

    archive_manifest = ArchiveManifest(archive_manifest_raw)
    config_digest = archive_manifest.get_config_digest()

    LOGGER.debug("Storing manifest for: %s ...", config_digest)
    await archive_image_source.put_manifest(archive_manifest, **kwargs)

    LOGGER.debug("Retrieving manifest for: %s ...", config_digest)
    manifest = await archive_image_source.get_manifest(
        ImageName("", digest=config_digest), **kwargs
    )
    assert isinstance(manifest, ArchiveManifest)
    # Note: Digest is not canonicalized (shifting RepoTags), and cannot be used for comparision
    # assert manifest.get_digest() == archive_manifest.get_digest()
    assert manifest.get_config_digest() == archive_manifest.get_config_digest()
    assert manifest.get_layers() == archive_manifest.get_layers()
    assert manifest.get_tags() == archive_manifest.get_tags()


async def test_sign_image_same_image_source(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test image signing."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    dest_image_name = image_name.clone()
    dest_image_name.digest = None
    dest_image_name.tag = __name__

    def assertions(result: ImageSourceSignImage):
        assert result

        image_config = result["image_config"]
        assert image_config
        assert "FAKE SIGNATURE" in str(image_config)

        signature_value = result["signature_value"]
        assert signature_value
        assert "FAKE SIGNATURE" in signature_value

        verify_image_data = result["verify_image_data"]
        assert verify_image_data
        assert image_config == verify_image_data["image_config"]

        manifest = verify_image_data["manifest"]
        assert manifest

        manifest_signed = result["manifest_signed"]
        assert manifest_signed
        assert manifest_signed.get_config_digest() == image_config.get_digest()
        assert len(manifest_signed.get_layers()) == len(image_config.get_image_layers())

    # 1. Single signature
    assertions(
        await archive_image_source.sign_image(
            FakeSigner(),
            image_name,
            archive_image_source,
            dest_image_name,
            SignatureTypes.SIGN,
            **kwargs,
        )
    )

    # TODO: Test signing image twice (with same key, with different keys ...)


async def test_sign_image_different_image_source(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test image signing."""
    archive_image_source_src = known_good_image_archive["archive_image_source"]
    archive_image_source_dest = ArchiveImageSource(
        archive=Path(archive_image_source_src.archive.parent, f"{__name__}.tar")
    )
    image_name = known_good_image_archive["image_name"]

    dest_image_name = image_name.clone()
    dest_image_name.digest = None
    dest_image_name.tag = __name__

    def assertions(result: ImageSourceSignImage):
        assert result

        image_config = result["image_config"]
        assert image_config
        assert "FAKE SIGNATURE" in str(image_config)

        signature_value = result["signature_value"]
        assert signature_value
        assert "FAKE SIGNATURE" in signature_value

        verify_image_data = result["verify_image_data"]
        assert verify_image_data
        assert image_config == verify_image_data["image_config"]

        manifest = verify_image_data["manifest"]
        assert manifest

        manifest_signed = result["manifest_signed"]
        assert manifest_signed
        assert manifest_signed.get_config_digest() == image_config.get_digest()
        assert len(manifest_signed.get_layers()) == len(image_config.get_image_layers())

    # 1. Single signature
    assertions(
        await archive_image_source_src.sign_image(
            FakeSigner(),
            image_name,
            archive_image_source_dest,
            dest_image_name,
            SignatureTypes.SIGN,
            **kwargs,
        )
    )

    # TODO: Test signing image twice (with same key, with different keys ...)


async def test_verify_image_integrity(
    known_good_image_archive: TypingKnownGoodImageArchive, **kwargs
):
    """Test image integrity verification."""
    archive_image_source = known_good_image_archive["archive_image_source"]
    image_name = known_good_image_archive["image_name"]

    def assertions(result: ImageSourceVerifyImageIntegrity):
        assert result

        image_config = result["image_config"]
        assert image_config

        manifest = result["manifest"]
        assert manifest

        # TODO: Uncomment if / when archive image source supports this ...
        # assert len(result["compressed_layer_files"]) == len(
        #     result["uncompressed_layer_files"]
        # )

    # 1. Unsigned
    assertions(await archive_image_source.verify_image_integrity(image_name, **kwargs))

    # TODO: Test integrity on a signed image ...
