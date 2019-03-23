#!/usr/bin/env python

"""RegistryV2ImageSource tests."""

import base64
import copy
import pytest
import tempfile


from docker_sign_verify import (
    ImageConfig,
    ImageName,
    RegistryV2ImageSource,
    RegistryV2Manifest,
)
from docker_sign_verify.utils import FormattedSHA256

from .stubs import FakeSigner
from .testutils import get_test_data_path

KNOWN_GOOD_IMAGE_LIST = ["busybox:1.30.1", "library/python:3.7.2-slim-stretch"]


@pytest.fixture
def registry_v2_image_source():
    # Do not use caching; get a new instance for each test
    return RegistryV2ImageSource(dry_run=True)


def test_init(registry_v2_image_source: RegistryV2ImageSource):
    """Test that the image source can be instantiated."""
    assert registry_v2_image_source


@pytest.mark.parametrize(
    "endpoint,expected_username,expected_password",
    [
        ("endpoint:port", "username", "password"),
        ("endpoint2:port2", "username2", "password2"),
    ],
)
def test__get_credentials(
    request,
    registry_v2_image_source: RegistryV2ImageSource,
    endpoint: str,
    expected_username: str,
    expected_password: str,
):
    """Test credentials retrieval."""
    registry_v2_image_source.credentials_store = get_test_data_path(
        request, "credentials_store.json"
    )
    credentials = registry_v2_image_source._get_credentials(endpoint)
    assert credentials

    decoded = base64.decodebytes(credentials.encode("utf-8")).decode("utf-8")
    assert decoded

    actual_username, actual_password = decoded.split(":")
    assert actual_username == expected_username
    assert actual_password == expected_password


@pytest.mark.parametrize(
    "image,expected_credentials",
    [
        ("endpoint:port/image", "dXNlcm5hbWU6cGFzc3dvcmQ="),
        ("endpoint2:port2/image", "dXNlcm5hbWUyOnBhc3N3b3JkMg=="),
    ],
)
def test__get_request_headers(
    request,
    registry_v2_image_source: RegistryV2ImageSource,
    image: str,
    expected_credentials: str,
):
    """Test request headers retrieval."""
    registry_v2_image_source.credentials_store = get_test_data_path(
        request, "credentials_store.json"
    )
    image_name = ImageName.parse(image)
    headers = registry_v2_image_source._get_request_headers(image_name)
    assert headers
    assert expected_credentials in headers["Authorization"]


@pytest.mark.parametrize("image", KNOWN_GOOD_IMAGE_LIST)
def test_get_iamge_config(registry_v2_image_source: RegistryV2ImageSource, image: str):
    """Test image configuration retrieval."""
    image_name = ImageName.parse(image)
    config = registry_v2_image_source.get_image_config(image_name)

    assert config
    assert type(config) == ImageConfig


@pytest.mark.parametrize("image", KNOWN_GOOD_IMAGE_LIST)
def test_get_image_layer_to_disk(
    registry_v2_image_source: RegistryV2ImageSource, image: str
):
    """Test layer retrieval to disk."""
    image_name = ImageName.parse(image)
    config_digest = registry_v2_image_source.get_manifest(
        image_name
    ).get_config_digest()
    temp = tempfile.NamedTemporaryFile()
    result = registry_v2_image_source.get_image_layer_to_disk(
        image_name, config_digest, temp
    )
    assert result["digest"] == config_digest


@pytest.mark.parametrize("image", KNOWN_GOOD_IMAGE_LIST)
def test_get_manifest(registry_v2_image_source: RegistryV2ImageSource, image: str):
    """Test manifest retrieval."""
    image_name = ImageName.parse(image)
    manifest = registry_v2_image_source.get_manifest(image_name)

    assert manifest
    assert type(manifest) == RegistryV2Manifest


@pytest.mark.parametrize("image", KNOWN_GOOD_IMAGE_LIST)
def test_layer_exists(registry_v2_image_source: RegistryV2ImageSource, image: str):
    """Test layer existence."""
    image_name = ImageName.parse(image)
    layer = registry_v2_image_source.get_manifest(image_name).get_layers()[-1]
    assert registry_v2_image_source.layer_exists(image_name, layer)
    assert not registry_v2_image_source.layer_exists(
        image_name, FormattedSHA256("0" * 64)
    )


@pytest.mark.parametrize("image", KNOWN_GOOD_IMAGE_LIST)
def test_sign_image_same_image_source(
    registry_v2_image_source: RegistryV2ImageSource, image: str
):
    """Test image signing."""
    src_image_name = ImageName.parse(image)
    dest_image_name = copy.deepcopy(src_image_name)
    dest_image_name.tag = "{0}_signed".format(dest_image_name.tag)

    def assertions(result: dict):
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
        assert manifest_signed.get_config_digest() == image_config.get_config_digest()
        assert len(manifest_signed.get_layers()) == len(image_config.get_image_layers())

    # 1. Single signature
    assertions(
        registry_v2_image_source.sign_image(
            FakeSigner(), src_image_name, registry_v2_image_source, dest_image_name
        )
    )

    # TODO: Test signing image twice (with same key, with different keys ...)
    #       Can we do this here (using dockerhub), or do we need to do this in test_imageconfig.py???


# TODO: test_sign_image_different_image_source


@pytest.mark.parametrize("image", KNOWN_GOOD_IMAGE_LIST)
def test_unsign_image_same_image_source(
    registry_v2_image_source: RegistryV2ImageSource, image: str
):
    """Test image unsigning."""
    src_image_name = ImageName.parse(image)
    dest_image_name = copy.deepcopy(src_image_name)
    dest_image_name.tag = "{0}_unsigned".format(dest_image_name.tag)

    def assertions(result: dict):
        assert result

        image_config = result["image_config"]
        assert image_config
        assert "FAKE SIGNATURE" not in str(image_config)

        verify_image_data = result["verify_image_data"]
        assert verify_image_data
        assert image_config == verify_image_data["image_config"]

        manifest = verify_image_data["manifest"]
        assert manifest

        manifest_unsigned = result["manifest_unsigned"]
        assert manifest_unsigned
        assert manifest_unsigned.get_config_digest() == image_config.get_config_digest()
        assert len(manifest_unsigned.get_layers()) == len(
            image_config.get_image_layers()
        )

    # 1. Pre signature
    assertions(
        registry_v2_image_source.unsign_image(
            src_image_name, registry_v2_image_source, dest_image_name
        )
    )

    # Sign
    registry_v2_image_source.sign_image(
        FakeSigner(), src_image_name, registry_v2_image_source, dest_image_name
    )

    # 2. Post signature
    assertions(
        registry_v2_image_source.unsign_image(
            src_image_name, registry_v2_image_source, dest_image_name
        )
    )


# TODO: test_unsign_image_different_image_source


@pytest.mark.parametrize("image", KNOWN_GOOD_IMAGE_LIST)
def test_verify_image_integrity(
    registry_v2_image_source: RegistryV2ImageSource, image: str
):
    """Test image unsigning."""
    image_name = ImageName.parse(image)

    def assertions(result: dict):
        assert result

        image_config = result["image_config"]
        assert image_config

        manifest = result["manifest"]
        assert manifest

        assert len(result["compressed_layer_files"]) == len(
            result["uncompressed_layer_files"]
        )

    # 1. Unsigned
    assertions(registry_v2_image_source.verify_image_integrity(image_name))

    # TODO: Test integrity on a signed image ...
    #       Can we do this here (using dockerhub), or do we need to do this in test_imageconfig.py???
