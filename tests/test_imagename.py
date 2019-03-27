#!/usr/bin/env python

"""ImageName tests."""

import pytest

from docker_sign_verify import ImageName


@pytest.fixture()
def url():
    return "endpoint:port/namespace/image:tag"


@pytest.fixture()
def image_name(url):
    return ImageName.parse(url)


def test_init():
    """Test that image name can be instantiated."""
    assert ImageName("endpoint:port", "namespace/image", "tag")


def test_str():
    """Test __str__ pass-through for different variants."""
    for endpoint in ["endpoint.io", "endpoint:port", None]:
        for image in ["image", "namespace/image"]:
            for tag in ["tag", None]:
                image_name = ImageName(endpoint, image, tag)
                string = str(image_name)
                assert image in string
                if endpoint:
                    assert endpoint in string
                if tag:
                    assert tag in string
                assert "None" not in string


def test_parse_string():
    """Test string parsing for complex image names."""
    for endpoint in ["endpoint.io", "endpoint:port", None]:
        for image in ["image", "namespace/image"]:
            for tag in ["tag", None]:

                # Construct a complex string ...
                string = image
                if tag:
                    string = "{0}:{1}".format(string, tag)
                if endpoint:
                    string = "{0}/{1}".format(endpoint, string)

                # Verify the complex string was parsed correctly ...
                result = ImageName._parse_string(string)
                assert result["endpoint"] == endpoint
                assert result["image"] == image
                assert result["tag"] == tag


def test_parse():
    """Test initialization via parsed strings."""
    (endpoint, image, tag) = ["address:port", "namespace/image", "tag"]
    image_name = ImageName.parse("{0}/{1}:{2}".format(endpoint, image, tag))
    assert image_name.endpoint == endpoint
    assert image_name.image == image
    assert image_name.tag == tag


def test_endpoint(image_name: ImageName):
    """Tests endpoint retrieval."""
    assert image_name.endpoint == "endpoint:port"


def test_image(image_name: ImageName):
    """Tests endpoint image."""
    assert image_name.image == "namespace/image"


def test_tag(image_name: ImageName):
    """Tests endpoint tag."""
    assert image_name.tag == "tag"


# TODO: Test resolve methods ...
