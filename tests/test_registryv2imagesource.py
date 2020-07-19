#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name

"""RegistryV2ImageSource tests."""

import logging

from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Dict

import aiofiles
import pytest

from docker_registry_client_async import FormattedSHA256
from docker_sign_verify import (
    ImageConfig,
    RegistryV2ImageSource,
    RegistryV2Manifest,
    SignatureTypes,
)
from docker_sign_verify.aiotempfile import open as aiotempfile
from docker_sign_verify.imagesource import (
    ImageSourceSignImage,
    ImageSourceVerifyImageIntegrity,
)

from .localregistry import (
    docker_client,
    known_good_image_local,
    known_good_image_remote,
    pytest_registry,
)  # Needed for pytest.fixtures
from .stubs import FakeSigner
from .testutils import hash_file

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


@pytest.fixture
async def registry_v2_image_source() -> RegistryV2ImageSource:
    """Provides a RegistryV2ImageSource instance."""
    # Do not use caching; get a new instance for each test
    # Implicitly tests __aenter__(), __aexit__(), and close()
    async with RegistryV2ImageSource() as registry_v2_image_source:
        yield registry_v2_image_source


def test___init__(registry_v2_image_source: RegistryV2ImageSource):
    """Test that the image source can be instantiated."""
    assert registry_v2_image_source


@pytest.mark.online
async def test_get_image_config(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test image configuration retrieval."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    config = await registry_v2_image_source.get_image_config(
        known_good_image_local["image_name"], **kwargs
    )
    assert isinstance(config, ImageConfig)


@pytest.mark.online
async def test_get_image_layer_to_disk(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test layer retrieval to disk."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image_local["image_name"], **kwargs
    )
    config_digest = manifest.get_config_digest()

    LOGGER.debug("Retrieving blob: %s/%s ...", config_digest, config_digest)
    async with aiotempfile(mode="w+b") as file:
        result = await registry_v2_image_source.get_image_layer_to_disk(
            known_good_image_local["image_name"], config_digest, file, **kwargs
        )
        LOGGER.debug("Verifying digest of written file ...")
        assert await hash_file(file.name) == config_digest
    assert result["digest"] == config_digest


@pytest.mark.online
async def test_get_manifest(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test manifest retrieval."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    LOGGER.debug(
        "Retrieving manifest for: %s ...", known_good_image_local["image_name"]
    )
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image_local["image_name"], **kwargs
    )
    assert isinstance(manifest, RegistryV2Manifest)
    assert (
        manifest.get_digest() == known_good_image_local["image_name"].resolve_digest()
    )


@pytest.mark.online
async def test_layer_exists(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test layer existence."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    LOGGER.debug(
        "Retrieving manifest for: %s ...", known_good_image_local["image_name"]
    )
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image_local["image_name"], **kwargs
    )
    layer = manifest.get_layers()[-1]
    assert await registry_v2_image_source.layer_exists(
        known_good_image_local["image_name"], layer, **kwargs
    )
    assert not await registry_v2_image_source.layer_exists(
        known_good_image_local["image_name"], FormattedSHA256("0" * 64), **kwargs
    )


# TODO async def test_put_image


@pytest.mark.online_modification
async def test_put_image_config(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test image configuration assignment."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image_local["image_name"],
    )
    image_config = await registry_v2_image_source.get_image_config(
        known_good_image_local["image_name"], **kwargs
    )

    # Modify the configuration
    json = image_config.get_json()
    labels = image_config._get_labels(json)
    labels["foo"] = datetime.now().strftime("%d%m%Y%H%M%S")
    image_config._set_json(json)

    LOGGER.debug(
        "Storing modified image configuration: %s ...", image_config.get_digest()
    )
    response = await registry_v2_image_source.put_image_config(
        known_good_image_local["image_name"], image_config, **kwargs
    )
    # Note: If NoneType, digest may already exist
    assert response["digest"] == image_config.get_digest()


@pytest.mark.online_modification
async def test_put_image(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test image layer assignment."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    image_name = known_good_image_local["image_name"]
    LOGGER.debug("Retrieving image: %s ...", image_name)
    response = await registry_v2_image_source.verify_image_integrity(
        image_name, **kwargs
    )

    image_name.tag += "_copy"

    LOGGER.debug("Storing image: %s ...", image_name)
    response = await registry_v2_image_source.put_image(
        registry_v2_image_source,
        image_name,
        response["manifest"],
        response["image_config"],
        response["compressed_layer_files"],
        **kwargs,
    )


@pytest.mark.online_modification
async def test_put_image_layer(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test image layer assignment."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image_local["image_name"],
    )
    image_config = await registry_v2_image_source.get_image_config(
        known_good_image_local["image_name"], **kwargs
    )

    # Modify the configuration
    json = image_config.get_json()
    labels = image_config._get_labels(json)
    labels["foo"] = datetime.now().strftime("%d%m%Y%H%M%S")
    image_config._set_json(json)

    LOGGER.debug(
        "Storing modified image configuration: %s ...", image_config.get_digest()
    )
    response = await registry_v2_image_source.put_image_layer(
        known_good_image_local["image_name"], image_config.get_bytes(), **kwargs
    )
    assert response["digest"] == image_config.get_digest()


@pytest.mark.online_modification
async def test_put_image_layer_from_disk(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    tmp_path: Path,
    **kwargs,
):
    """Test image layer assignment from disk."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image_local["image_name"],
    )
    image_config = await registry_v2_image_source.get_image_config(
        known_good_image_local["image_name"], **kwargs
    )

    # Modify the configuration
    json = image_config.get_json()
    labels = image_config._get_labels(json)
    labels["foo"] = datetime.now().strftime("%d%m%Y%H%M%S")
    image_config._set_json(json)

    LOGGER.debug("Writing modified configuration to disk ...")
    path = tmp_path.joinpath("image_config.json")
    async with aiofiles.open(path, mode="w+b") as file:
        await file.write(image_config.get_bytes())

    LOGGER.debug(
        "Storing modified image configuration: %s ...", image_config.get_digest()
    )
    async with aiofiles.open(path, mode="r+b") as file:
        response = await registry_v2_image_source.put_image_layer_from_disk(
            known_good_image_local["image_name"], file, **kwargs
        )
    assert response["digest"] == image_config.get_digest()


@pytest.mark.online_modification
async def test_put_manifest(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test manifest assignment."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    LOGGER.debug(
        "Retrieving manifest for: %s ...", known_good_image_local["image_name"]
    )
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image_local["image_name"], **kwargs
    )
    assert isinstance(manifest, RegistryV2Manifest)
    assert (
        manifest.get_digest() == known_good_image_local["image_name"].resolve_digest()
    )

    LOGGER.debug("Storing manifest for: %s ...", known_good_image_local["image_name"])
    response = await registry_v2_image_source.put_manifest(
        manifest, known_good_image_local["image_name"], **kwargs
    )
    assert response["digest"] == known_good_image_local["image_name"].resolve_digest()


@pytest.mark.online_modification
async def test_sign_image_same_image_source(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test image signing."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]
    dest_image_name = deepcopy(known_good_image_local["image_name"])
    dest_image_name.digest = None
    dest_image_name.tag = "{0}_signed".format(dest_image_name.tag)

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
        await registry_v2_image_source.sign_image(
            FakeSigner(),
            known_good_image_local["image_name"],
            registry_v2_image_source,
            dest_image_name,
            SignatureTypes.SIGN,
            **kwargs,
        )
    )

    # TODO: Test signing image twice (with same key, with different keys ...)
    #       Can we do this here (using dockerhub), or do we need to do this in test_imageconfig.py???


# TODO: test_sign_image_different_image_source


@pytest.mark.online
async def test_verify_image_integrity(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image_local: Dict,
    **kwargs,
):
    """Test image integrity verification."""
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    def assertions(result: ImageSourceVerifyImageIntegrity):
        assert result

        image_config = result["image_config"]
        assert image_config

        manifest = result["manifest"]
        assert manifest

        assert len(result["compressed_layer_files"]) == len(
            result["uncompressed_layer_files"]
        )

        assert len(result["uncompressed_layer_files"]) == len(
            result["uncompressed_layer_files"]
        )

    # 1. Unsigned
    assertions(
        await registry_v2_image_source.verify_image_integrity(
            known_good_image_local["image_name"], **kwargs
        )
    )

    # TODO: Test integrity on a signed image ...
    #       Can we do this here (using dockerhub), or do we need to do this in test_imageconfig.py???
