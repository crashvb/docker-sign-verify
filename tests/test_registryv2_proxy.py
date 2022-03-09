#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name

"""RegistryV2 tests."""

import asyncio
import json
import logging

from datetime import datetime
from pathlib import Path
from ssl import create_default_context
from time import time
from typing import cast

import aiofiles
import pytest

from aiohttp.helpers import BasicAuth
from docker_registry_client_async import (
    DockerMediaTypes,
    ImageName,
)
from pytest_docker_registry_fixtures import DockerRegistrySecure
from pytest_docker_squid_fixtures import SquidSecure

from docker_sign_verify import (
    ImageConfig,
    NoSignatureError,
    RegistryV2,
    RegistryV2Manifest,
    RegistryV2ManifestList,
    RegistryV2SignImage,
    RegistryV2VerifyImageConfig,
    RegistryV2VerifyImageIntegrity,
    Signer,
    SignatureTypes,
)

from .conftest import (
    get_test_data,
    _pytestmark,
    TypingGetTestData,
    TypingKnownGoodImage,
)
from .stubs import (
    _signer_for_signature,
    FakeSigner,
    FakeSignerVerify,
)
from .test_registryv2 import (
    credentials_store_path,  # Needed for pytest
    image_name,  # Needed for pytest
    replicate_manifest_lists,  # Needed for pytest
)

pytestmark = [pytest.mark.asyncio, *_pytestmark]

LOGGER = logging.getLogger(__name__)

# Bug Fix: https://github.com/crashvb/docker-registry-client-async/issues/24
#
# Right now this is known to leave a nasty "Fatal error on SSL transport" error
# at the end of the test execution; however, without this we cannot test using
# a TLS-in-TLS proxy ...
setattr(asyncio.sslproto._SSLProtocolTransport, "_start_tls_compatible", True)


@pytest.fixture(scope="session")
# Required for asynchronous, session-scoped, fixtures
def event_loop():
    """Create an instance of the default event loop once for the session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
# HACK: Invoke replicate_manifest_lists fixture to tell PDRF about the manifest lists we use for testing ...
async def registry_v2_image_source_proxy(
    credentials_store_path: Path,
    docker_registry_secure: DockerRegistrySecure,
    replicate_manifest_lists,
    squid_secure: SquidSecure,
) -> RegistryV2:
    # pylint: disable=unused-argument
    """Provides a RegistryV2 instance."""
    ssl_context = create_default_context(
        cadata=squid_secure.certs.ca_certificate.read_text("utf-8")
        + docker_registry_secure.certs.ca_certificate.read_text("utf-8")
    )
    # Do not use caching; get a new instance for each test
    async with RegistryV2(
        credentials_store=credentials_store_path, ssl=ssl_context
    ) as registry_v2_image_source_proxy:
        credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
        for name in [
            docker_registry_secure.endpoint,
            docker_registry_secure.endpoint_name,
        ]:
            await registry_v2_image_source_proxy.docker_registry_client_async.add_credentials(
                name, credentials
            )
        registry_v2_image_source_proxy.docker_registry_client_async.proxies[
            "https"
        ] = f"https://{squid_secure.endpoint}/"
        registry_v2_image_source_proxy.docker_registry_client_async.proxy_auth = (
            BasicAuth(login=squid_secure.username, password=squid_secure.password)
        )

        yield registry_v2_image_source_proxy


@pytest.mark.online
async def test___init__(registry_v2_image_source_proxy: RegistryV2):
    """Test that the image source can be instantiated."""
    assert registry_v2_image_source_proxy


@pytest.mark.online
async def test__verify_image_config(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test verifying the integrity of the image configuration."""

    def assertions(result: RegistryV2VerifyImageConfig):
        assert result

        image_config = result.image_config
        assert image_config
        assert json.loads(image_config.get_bytes())

        image_layers = result.image_layers
        assert image_layers

        manifest = result.manifest
        assert manifest
        assert manifest.get_config_digest() == image_config.get_digest()
        assert json.loads(image_config.get_bytes())

        manifest_layers = result.manifest_layers
        assert manifest_layers
        assert len(image_layers) == len(manifest_layers)

    # 1. Pre signature
    # pylint: disable=protected-access
    assertions(
        await registry_v2_image_source_proxy._verify_image_config(
            image_name=known_good_image_proxy.image_name
        )
    )

    # Sign
    image_name_dest = (
        known_good_image_proxy.image_name.clone()
        .set_digest()
        .set_tag(test__verify_image_config.__name__)
    )
    await registry_v2_image_source_proxy.sign_image(
        image_name_dest=image_name_dest,
        image_name_src=known_good_image_proxy.image_name,
        signer=FakeSigner(),
    )

    # 2. Post signature
    # pylint: disable=protected-access
    assertions(
        await registry_v2_image_source_proxy._verify_image_config(
            image_name=image_name_dest
        )
    )


@pytest.mark.online
async def test_get_image_config(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test image configuration retrieval."""
    LOGGER.debug(
        "Retrieving image configuration for: %s ...", known_good_image_proxy.image_name
    )
    image_config = await registry_v2_image_source_proxy.get_image_config(
        image_name=known_good_image_proxy.image_name
    )
    assert isinstance(image_config, ImageConfig)


@pytest.mark.online
async def test_get_manifest(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test manifest retrieval."""
    LOGGER.debug("Retrieving manifest for: %s ...", known_good_image_proxy.image_name)
    manifest = await registry_v2_image_source_proxy.get_manifest(
        image_name=known_good_image_proxy.image_name
    )
    assert isinstance(manifest, RegistryV2Manifest)
    assert manifest.get_digest() == known_good_image_proxy.image_name.resolve_digest()


@pytest.mark.online
@pytest.mark.parametrize("image", get_test_data())
async def test_get_manifest_list(
    docker_registry_secure: DockerRegistrySecure,
    image: TypingGetTestData,
    registry_v2_image_source_proxy: RegistryV2,
):
    """Test manifest retrieval."""
    if not image.tag_resolves_to_manifest_list:
        pytest.skip(f"Image {image.image} does not reference a manifest list.")

    image_name = ImageName(
        image.image,
        digest=image.digests[DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2],
        endpoint=docker_registry_secure.endpoint_name,
        tag=image.tag,
    )

    LOGGER.debug("Retrieving manifest list for: %s ...", image_name)
    manifest = await registry_v2_image_source_proxy.get_manifest(image_name=image_name)
    assert isinstance(manifest, RegistryV2ManifestList)
    assert manifest.get_digest() == image_name.resolve_digest()


@pytest.mark.online_modification
async def test_put_image(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test image layer assignment."""
    image_name = known_good_image_proxy.image_name
    LOGGER.debug("Retrieving image: %s ...", image_name)
    response = await registry_v2_image_source_proxy.verify_image_integrity(
        image_name=image_name
    )

    image_name.tag += test_put_image.__name__

    LOGGER.debug("Storing image: %s ...", image_name)
    await registry_v2_image_source_proxy.put_image(
        image_config=response.image_config,
        image_name=image_name,
        layer_files=response.compressed_layer_files,
        manifest=response.manifest,
        manifest_list=response.manifest_list,
    )

    for file in response.compressed_layer_files + response.uncompressed_layer_files:
        file.close()


@pytest.mark.online_modification
async def test_put_image_config(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test image configuration assignment."""
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image_proxy.image_name,
    )
    image_config = await registry_v2_image_source_proxy.get_image_config(
        image_name=known_good_image_proxy.image_name
    )

    # Modify the configuration
    _json = image_config.get_json()
    labels = image_config._get_labels(_json)
    labels["foo"] = datetime.now().strftime("%d%m%Y%H%M%S")
    image_config._set_json(_json)

    LOGGER.debug(
        "Storing modified image configuration: %s ...", image_config.get_digest()
    )
    response = await registry_v2_image_source_proxy.put_image_config(
        image_config=image_config, image_name=known_good_image_proxy.image_name
    )
    # Note: If NoneType, digest may already exist
    assert response.digest == image_config.get_digest()


@pytest.mark.online_modification
async def test_put_image_layer_from_disk(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test image layer assignment from disk."""
    LOGGER.debug(
        "Retrieving image configuration for: %s ...",
        known_good_image_proxy.image_name,
    )
    image_config = await registry_v2_image_source_proxy.get_image_config(
        image_name=known_good_image_proxy.image_name
    )

    # Modify the configuration
    _json = image_config.get_json()
    labels = image_config._get_labels(_json)
    labels["foo"] = datetime.now().strftime("%d%m%Y%H%M%S")
    image_config._set_json(_json)

    LOGGER.debug("Writing modified configuration to disk ...")
    path = tmp_path.joinpath("image_config.json")
    async with aiofiles.open(path, mode="w+b") as file:
        await file.write(image_config.get_bytes())

    LOGGER.debug(
        "Storing modified image configuration: %s ...", image_config.get_digest()
    )
    async with aiofiles.open(path, mode="r+b") as file:
        response = await registry_v2_image_source_proxy.put_image_layer_from_disk(
            file=file, image_name=known_good_image_proxy.image_name
        )
    assert response.digest == image_config.get_digest()


@pytest.mark.online_modification
async def test_sign_image_same_image_source(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test image signing."""
    dest_image_name = known_good_image_proxy.image_name.clone().set_digest()
    dest_image_name.tag += "_signed"

    def assertions(result: RegistryV2SignImage):
        assert result

        image_config = result.image_config
        assert image_config
        assert "FAKE SIGNATURE" in str(image_config)

        signature_value = result.signature_value
        assert signature_value
        assert "FAKE SIGNATURE" in signature_value

        verify_image_data = result.verify_image_data
        assert verify_image_data
        assert image_config == verify_image_data.image_config

        manifest = verify_image_data.manifest
        assert manifest

        manifest_signed = result.manifest_signed
        assert manifest_signed
        assert manifest_signed.get_config_digest() == image_config.get_digest()
        assert len(manifest_signed.get_layers()) == len(image_config.get_image_layers())

    # 1. Single signature
    response = await registry_v2_image_source_proxy.sign_image(
        image_name_src=known_good_image_proxy.image_name,
        image_name_dest=dest_image_name,
        signature_type=SignatureTypes.SIGN,
        signer=FakeSigner(),
    )
    assertions(response)

    for file in (
        response.verify_image_data.compressed_layer_files
        + response.verify_image_data.uncompressed_layer_files
    ):
        file.close()

    # TODO: Test signing image twice (with same key, with different keys ...)
    #       Can we do this here (using dockerhub), or do we need to do this in test_imageconfig.py???


# TODO: test_sign_image_different_image_source


@pytest.mark.online
async def test_verify_image_integrity(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test image integrity verification."""

    def assertions(result: RegistryV2VerifyImageIntegrity):
        assert result

        image_config = result.image_config
        assert image_config

        manifest = result.manifest
        assert manifest

        assert len(result.compressed_layer_files) == len(
            result.uncompressed_layer_files
        )

    # 1. Unsigned
    response = await registry_v2_image_source_proxy.verify_image_integrity(
        image_name=known_good_image_proxy.image_name
    )
    assertions(response)

    for file in response.compressed_layer_files + response.uncompressed_layer_files:
        file.close()

    # TODO: Test integrity on a signed image ...
    #       Can we do this here (using dockerhub), or do we need to do this in test_imageconfig.py???


async def test_verify_image_signatures(
    registry_v2_image_source_proxy: RegistryV2,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test verifying the signatures within the image configuration."""
    # An exception should be raised if the image configuration is not signed
    with pytest.raises(NoSignatureError) as exception:
        await registry_v2_image_source_proxy.verify_image_signatures(
            image_name=known_good_image_proxy.image_name
        )
    assert str(exception.value) == "Image does not contain any signatures!"

    # Sign
    image_name_dest = (
        known_good_image_proxy.image_name.clone()
        .set_digest()
        .set_tag(test_verify_image_signatures.__name__)
    )
    await registry_v2_image_source_proxy.sign_image(
        image_name_dest=image_name_dest,
        image_name_src=known_good_image_proxy.image_name,
        signer=FakeSigner(),
    )

    # Replace the class method for resolving signature providers ...
    original_method = Signer.for_signature
    Signer.for_signature = _signer_for_signature

    result = await registry_v2_image_source_proxy.verify_image_signatures(
        image_name=image_name_dest
    )
    assert result.image_config
    assert result.signatures

    # Make sure that signer_kwargs are passed correctly ...
    assignable_value = time()
    registry_v2_image_source_proxy.signer_kwargs = {
        FakeSigner.__name__: {"assignable_value": assignable_value}
    }
    result = await registry_v2_image_source_proxy.verify_image_signatures(
        image_name=image_name_dest
    )
    assert result.image_config
    assert result.signatures
    fake_signer_verify = cast(FakeSignerVerify, result.signatures.results[0])
    assert fake_signer_verify.assignable_value == assignable_value
    assert fake_signer_verify.type == "fake"
    assert fake_signer_verify.valid

    # Restore the original class method
    Signer.for_signature = original_method
