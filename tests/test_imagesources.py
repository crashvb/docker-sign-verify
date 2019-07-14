#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""ImageSource tests."""

import json
import pytest

from docker_sign_verify import ImageName, ImageSource, Signer

from .stubs import _signer_for_signature, FakeRegistryV2ImageSourceNoLabels
from .test_imagename import image_name, url

# TODO: Additionally, test all methods with config.json that *does* contain 'Labels' ...


@pytest.fixture
def fake_registry_v2_image_source(request) -> FakeRegistryV2ImageSourceNoLabels:
    """Provides a fake RegistryV2ImageSource without"""
    # Do not use caching; get a new instance for each test
    return FakeRegistryV2ImageSourceNoLabels(request, layer_exists=True, dry_run=True)


def test_init(fake_registry_v2_image_source: ImageSource):
    """Test that the image source can be instantiated."""
    assert fake_registry_v2_image_source


def test__sign_image_config(
    fake_registry_v2_image_source: FakeRegistryV2ImageSourceNoLabels,
    image_name: ImageName,
):
    """Test adding signature(s) to the image configuration."""
    result = fake_registry_v2_image_source.quick_sign(image_name)
    assert result

    image_config = result["image_config"]
    assert image_config
    assert "FAKE SIGNATURE" in str(image_config)
    assert json.loads(image_config.get_config())

    signature_value = result["signature_value"]
    assert signature_value
    assert "FAKE SIGNATURE" in signature_value

    verify_image_data = result["verify_image_data"]
    assert verify_image_data
    assert image_config == verify_image_data["image_config"]

    manifest = verify_image_data["manifest"]
    assert manifest
    assert manifest.get_config_digest() == image_config.get_config_digest()
    assert len(manifest.get_layers()) == len(image_config.get_image_layers())


def test__verify_image_config(
    fake_registry_v2_image_source: FakeRegistryV2ImageSourceNoLabels,
    image_name: ImageName,
):
    """Test verifying the integrity of the image configuration."""

    def assertions(result: dict):
        assert result

        image_config = result["image_config"]
        assert image_config
        assert json.loads(image_config.get_config())

        image_layers = result["image_layers"]
        assert image_layers

        manifest = result["manifest"]
        assert manifest
        assert manifest.get_config_digest() == image_config.get_config_digest()
        assert json.loads(image_config.get_config())

        manifest_layers = result["manifest_layers"]
        assert manifest_layers
        assert len(image_layers) == len(manifest_layers)

    # 1. Pre signature
    # pylint: disable=protected-access
    assertions(fake_registry_v2_image_source._verify_image_config(image_name))

    # Sign
    fake_registry_v2_image_source.quick_sign(image_name)

    # 2. Post signature
    # pylint: disable=protected-access
    assertions(fake_registry_v2_image_source._verify_image_config(image_name))


def test_verify_image_signatures(
    fake_registry_v2_image_source: FakeRegistryV2ImageSourceNoLabels,
    image_name: ImageName,
):
    """Test verifying the signatures within the image configuration."""
    # An exception should be raised if the image configuration is not signed
    with pytest.raises(Exception) as exception:
        fake_registry_v2_image_source.verify_image_signatures(image_name)
    assert str(exception.value) == "Image does not contain any signatures!"

    # Sign
    fake_registry_v2_image_source.quick_sign(image_name)

    # Replace the class method for resolving signature providers ...
    original_method = Signer.for_signature
    Signer.for_signature = _signer_for_signature

    result = fake_registry_v2_image_source.verify_image_signatures(image_name)
    assert result["image_config"]
    assert result["signatures"]

    # Restore the original class method
    Signer.for_signature = original_method
