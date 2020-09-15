#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name

"""RegistryV2ImageSource tests."""

import asyncio
import logging

from datetime import datetime
from pathlib import Path

import aiofiles
import pytest

from docker_registry_client_async import (
    DockerAuthentication,
    DockerMediaTypes,
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
)
from pytest_docker_registry_fixtures import (
    DockerRegistrySecure,
    ImageName as PDRFImageName,
    replicate_manifest_list,
)

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

from .conftest import (
    get_test_data_registryv2,
    _pytestmark,
    TypingGetTestData,
    TypingKnownGoodImage,
)
from .stubs import FakeSigner
from .testutils import get_test_data_path, hash_file

LOGGER = logging.getLogger(__name__)

pytestmark = [pytest.mark.asyncio, *_pytestmark]


@pytest.fixture
def credentials_store_path(request) -> Path:
    """Retrieves the path of the credentials store to use for testing."""
    return get_test_data_path(request, "credentials_store.json")


@pytest.fixture(scope="session")
# Required for asynchronous, session-scoped, fixtures
def event_loop():
    """Create an instance of the default event loop once for the session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
# HACK: Invoke replicate_manifest_list fixture to tell PDRF about the manifest lists we use for testing ...
async def registry_v2_image_source(
    credentials_store_path: Path,
    docker_registry_secure: DockerRegistrySecure,
    replicate_manifest_lists,
) -> RegistryV2ImageSource:
    """Provides a RegistryV2ImageSource instance."""
    # Do not use caching; get a new instance for each test
    async with RegistryV2ImageSource(
        credentials_store=credentials_store_path, ssl=docker_registry_secure.ssl_context
    ) as registry_v2_image_source:
        credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
        await registry_v2_image_source.docker_registry_client_async.add_credentials(
            docker_registry_secure.endpoint, credentials
        )

        yield registry_v2_image_source


@pytest.fixture(scope="session")
async def replicate_manifest_lists(docker_registry_secure: DockerRegistrySecure):
    """Replicates manifests lists to the secure docker registry for testing."""
    # pylint: disable=protected-access
    LOGGER.debug(
        "Replicating manifest lists into %s ...", docker_registry_secure.service_name
    )
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        for image in get_test_data_registryv2():
            if "tag_resolves_to_manifest_list" not in image:
                continue

            digest = image["digests"][DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2]
            image_name = ImageName(image["image"], digest=digest, tag=image["tag"])
            LOGGER.debug("- %s", image_name)

            scope = DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.image
            )
            auth_header_src = await docker_registry_client_async._get_request_headers(
                image_name, scope=scope
            )
            if not auth_header_src:
                LOGGER.warning(
                    "Unable to retrieve authentication headers for: %s", image_name
                )

            pdrf_image_name = PDRFImageName(
                image_name.resolve_image(),
                digest=image_name.resolve_digest(),
                endpoint=image_name.resolve_endpoint(),
                tag=image_name.resolve_tag(),
            )
            try:
                replicate_manifest_list(
                    pdrf_image_name,
                    docker_registry_secure.endpoint,
                    auth_header_dest=docker_registry_secure.auth_header,
                    auth_header_src=auth_header_src,
                    ssl_context_dest=docker_registry_secure.ssl_context,
                )
            except Exception as exception:  # pylint: disable=broad-except
                LOGGER.warning(
                    "Unable to replicate manifest list '%s': %s",
                    image_name,
                    exception,
                    exc_info=True,
                )


def test___init__(registry_v2_image_source: RegistryV2ImageSource):
    """Test that the image source can be instantiated."""
    assert registry_v2_image_source


@pytest.mark.online
async def test_get_image_config(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test image configuration retrieval."""
    LOGGER.debug(
        "Retrieving image configuration for: %s ...", known_good_image["image_name"]
    )
    image_config = await registry_v2_image_source.get_image_config(
        known_good_image["image_name"], **kwargs
    )
    assert isinstance(image_config, ImageConfig)


@pytest.mark.online
async def test_get_image_layer_to_disk(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test layer retrieval to disk."""
    LOGGER.debug("Retrieving manifest for: %s ...", known_good_image["image_name"])
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image["image_name"], **kwargs
    )
    config_digest = manifest.get_config_digest()

    LOGGER.debug(
        "Retrieving blob: %s/%s ...", known_good_image["image_name"], config_digest
    )
    async with aiotempfile(mode="w+b") as file:
        result = await registry_v2_image_source.get_image_layer_to_disk(
            known_good_image["image_name"], config_digest, file, **kwargs
        )
        LOGGER.debug("Verifying digest of written file ...")
        assert await hash_file(file.name) == config_digest
    assert result["digest"] == config_digest


@pytest.mark.online
async def test_get_manifest(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test manifest retrieval."""
    LOGGER.debug("Retrieving manifest for: %s ...", known_good_image["image_name"])
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image["image_name"], **kwargs
    )
    assert isinstance(manifest, RegistryV2Manifest)
    assert manifest.get_digest() == known_good_image["image_name"].resolve_digest()


@pytest.mark.online
@pytest.mark.parametrize("image", get_test_data_registryv2())
async def test_get_manifest_list(
    docker_registry_secure: DockerRegistrySecure,
    image: TypingGetTestData,
    registry_v2_image_source: RegistryV2ImageSource,
    **kwargs,
):
    """Test manifest retrieval."""
    if "tag_resolves_to_manifest_list" not in image:
        pytest.skip(f"Image {image['image']} does not reference a manifest list.")

    image_name = ImageName(
        image["image"],
        digest=image["digests"][DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2],
        endpoint=docker_registry_secure.endpoint,
        tag=image["tag"],
    )

    LOGGER.debug("Retrieving manifest list for: %s ...", image_name)
    manifest = await registry_v2_image_source.get_manifest(image_name, **kwargs)
    assert isinstance(manifest, RegistryV2Manifest)
    assert manifest.get_digest() == image_name.resolve_digest()


@pytest.mark.online
async def test_layer_exists(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test layer existence."""
    LOGGER.debug("Retrieving manifest for: %s ...", known_good_image["image_name"])
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image["image_name"], **kwargs
    )
    layer = manifest.get_layers()[-1]
    assert await registry_v2_image_source.layer_exists(
        known_good_image["image_name"], layer, **kwargs
    )
    assert not await registry_v2_image_source.layer_exists(
        known_good_image["image_name"], FormattedSHA256("0" * 64), **kwargs
    )


@pytest.mark.online_modification
async def test_put_image(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test image layer assignment."""
    image_name = known_good_image["image_name"]
    LOGGER.debug("Retrieving image: %s ...", image_name)
    response = await registry_v2_image_source.verify_image_integrity(
        image_name, **kwargs
    )

    image_name.tag += __name__

    LOGGER.debug("Storing image: %s ...", image_name)
    await registry_v2_image_source.put_image(
        registry_v2_image_source,
        image_name,
        response["manifest"],
        response["image_config"],
        response["compressed_layer_files"],
        **kwargs,
    )


@pytest.mark.online_modification
async def test_put_image_config(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test image configuration assignment."""
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image["image_name"],
    )
    image_config = await registry_v2_image_source.get_image_config(
        known_good_image["image_name"], **kwargs
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
        known_good_image["image_name"], image_config, **kwargs
    )
    # Note: If NoneType, digest may already exist
    assert response["digest"] == image_config.get_digest()


@pytest.mark.online_modification
async def test_put_image_layer(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test image layer assignment."""
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image["image_name"],
    )
    image_config = await registry_v2_image_source.get_image_config(
        known_good_image["image_name"], **kwargs
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
        known_good_image["image_name"], image_config.get_bytes(), **kwargs
    )
    assert response["digest"] == image_config.get_digest()


@pytest.mark.online_modification
async def test_put_image_layer_from_disk(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test image layer assignment from disk."""
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image["image_name"],
    )
    image_config = await registry_v2_image_source.get_image_config(
        known_good_image["image_name"], **kwargs
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
            known_good_image["image_name"], file, **kwargs
        )
    assert response["digest"] == image_config.get_digest()


@pytest.mark.online_modification
async def test_put_manifest(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test manifest assignment."""
    LOGGER.debug("Retrieving manifest for: %s ...", known_good_image["image_name"])
    manifest = await registry_v2_image_source.get_manifest(
        known_good_image["image_name"], **kwargs
    )
    assert isinstance(manifest, RegistryV2Manifest)
    assert manifest.get_digest() == known_good_image["image_name"].resolve_digest()

    LOGGER.debug("Storing manifest for: %s ...", known_good_image["image_name"])
    response = await registry_v2_image_source.put_manifest(
        manifest, known_good_image["image_name"], **kwargs
    )
    assert response["digest"] == known_good_image["image_name"].resolve_digest()


@pytest.mark.online_modification
async def test_sign_image_same_image_source(
    registry_v2_image_source: RegistryV2ImageSource,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test image signing."""
    dest_image_name = known_good_image["image_name"].clone()
    dest_image_name.digest = None
    dest_image_name.tag = f"{dest_image_name.tag}_signed"

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
            known_good_image["image_name"],
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
    known_good_image: TypingKnownGoodImage,
    **kwargs,
):
    """Test image integrity verification."""

    def assertions(result: ImageSourceVerifyImageIntegrity):
        assert result

        image_config = result["image_config"]
        assert image_config

        manifest = result["manifest"]
        assert manifest

        assert len(result["compressed_layer_files"]) == len(
            result["uncompressed_layer_files"]
        )

    # 1. Unsigned
    assertions(
        await registry_v2_image_source.verify_image_integrity(
            known_good_image["image_name"], **kwargs
        )
    )

    # TODO: Test integrity on a signed image ...
    #       Can we do this here (using dockerhub), or do we need to do this in test_imageconfig.py???
