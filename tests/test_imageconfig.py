import pytest

from docker_sign_verify import ImageConfig, Signer
from pathlib import Path


@pytest.fixture
def json_bytes(request):
    return _get_test_data(request, "config.json")


@pytest.fixture
def json_bytes_canonical(request):
    return _get_test_data(request, "config_canonical.json")


@pytest.fixture
def json_bytes_signed(request):
    return _get_test_data(request, "config_signed.json")


@pytest.fixture
def config_digest(request):
    return _get_test_data(request, "config.json.digest", "r")


@pytest.fixture
def config_digest_canonical(request):
    return _get_test_data(request, "config_canonical.json.digest", "r")


@pytest.fixture
def config_digest_signed(request):
    return _get_test_data(request, "config_signed.json.digest", "r")


@pytest.fixture
def image_layers():
    return [
        "sha256:94b2db70f7476c98f4c4a1b7a922136e0c5600d2d74905407ad364dcca2bf852",
        "sha256:22426f366c51f26105aa9a6c6c9aea9fff0f21b7aabfc97870727577edaa3260",
    ]


@pytest.fixture
def image_config(json_bytes):
    # Do not use caching; get a new instance for each test
    return ImageConfig(json_bytes)


@pytest.fixture
def image_config_signed(json_bytes_signed):
    # Do not use caching; get a new instance for each test
    return ImageConfig(json_bytes_signed)


@pytest.fixture
def signature(request):
    return _get_test_data(request, "signature", "r")


def test_init(image_config: ImageConfig, image_config_signed: ImageConfig):
    """Test that signed and unsigned configurations can be instantiated."""
    assert image_config
    assert image_config_signed


def test_str(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes: bytes,
    json_bytes_signed: bytes,
):
    """Test __str__ pass-through for signed and unsigned configurations (with encoding)."""
    assert str(image_config) == json_bytes.decode("utf-8")
    assert str(image_config_signed) == json_bytes_signed.decode("utf-8")


def test_get_config(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes: bytes,
    json_bytes_signed: bytes,
):
    """Test get_config() pass-through for signed and unsigned configurations."""
    assert image_config.get_config() == json_bytes
    assert image_config_signed.get_config() == json_bytes_signed


def test_get_config_canonical(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    json_bytes_canonical: bytes,
):
    """Test the canonical form for signed and unsigned configurations."""
    assert image_config.get_config_canonical() == json_bytes_canonical
    assert image_config_signed.get_config_canonical() == json_bytes_canonical


def test_get_config_digest(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest: str,
    config_digest_signed: str,
):
    """Test digest calculation for signed and unsigned configurations."""
    assert image_config.get_config_digest() == config_digest
    assert image_config_signed.get_config_digest() == config_digest_signed


def test_get_config_digest_canonical(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest_canonical: str,
):
    """Test canonical digest calculation for signed and unsigned configurations."""
    assert image_config.get_config_digest_canonical() == config_digest_canonical
    assert image_config_signed.get_config_digest_canonical() == config_digest_canonical


def test_get_image_layers(
    image_config: ImageConfig, image_config_signed: ImageConfig, image_layers: list
):
    """Test image layer preservation for signed and unsigned configurations."""
    assert image_config.get_image_layers() == image_layers
    assert image_config_signed.get_image_layers() == image_layers


def test_get_signature_data(
    image_config: ImageConfig,
    image_config_signed: ImageConfig,
    config_digest: str,
    signature: str,
):
    """Test signature data parsing for signed and unsigned configurations."""
    signature_data_signed = image_config_signed.get_signature_data()
    assert signature_data_signed["original_config"] == config_digest
    assert signature_data_signed["signatures"] == signature
    assert signature_data_signed["signature_list"] == [signature]

    signature_data_unsigned = image_config.get_signature_data()
    assert signature_data_unsigned["original_config"] is None
    assert signature_data_unsigned["signatures"] == ""
    assert signature_data_unsigned["signature_list"] == []


def test_sign(image_config: ImageConfig, image_config_signed: ImageConfig):
    """Test configuration signing for signed and unsigned configurations."""

    # Initialize a fake signer with a predetermined signature value.
    signature_value = (
        "-----BEGIN FAKE SIGNATURE-----\nFAKE FAKE FAKE\n-----END FAKE SIGNATURE-----"
    )
    signer = FakeSigner(signature_value)

    assert image_config.sign(signer) == signature_value
    assert image_config_signed.sign(signer) == signature_value

    # Previously unsigned configurations should now contain the new signature.
    assert b"BEGIN FAKE SIGNATURE" in image_config.get_config()

    # Previously signed configurations should now contain the original signature(s) and the new signature.
    assert b"BEGIN FAKE SIGNATURE" in image_config_signed.get_config()
    assert b"BEGIN PGP SIGNATURE" in image_config_signed.get_config()


def test_verify_signatures(image_config: ImageConfig):
    """Test signature verification for signed and unsigned configurations."""

    # Unsigned configurations should explicitly raise an exception.
    with pytest.raises(Exception) as e:
        image_config.verify_signatures()
    assert str(e.value) == "Image does not contain any signatures!"

    # Sign a previously unsigned configuration, so that only the new signature type is present.
    # Note: It is not trivial to embed "known" GPG / PKI signature types, as assumptions about the
    #       test environment are difficult to make.
    image_config.sign(FakeSigner())

    # An exception should be raised if the provider for a signature type is not known
    with pytest.raises(Exception) as e:
        image_config.verify_signatures()
    assert str(e.value) == "Unsupported signature type!"

    # Replace the classmethod for resolving signature providers ...
    original_method = Signer.for_signature
    Signer.for_signature = _signer_for_signature

    # The Signer's verify() method should be invoked.
    assert image_config.verify_signatures()["results"] == [
        {"type": "fake", "valid": True}
    ]

    # Restore the original classmethod
    Signer.for_signature = original_method


def _get_test_data(request, name, mode="rb"):
    """Helper method to retrieve test data."""
    key = "imageconfig/{0}".format(name)
    result = request.config.cache.get(key, None)
    if result is None:
        path = Path(request.fspath).parent.joinpath(name)
        with open(path, mode) as file:
            result = file.read()
            # TODO: How do we / Should we serialize binary data?
            # request.config.cache.set(key, result)
    return result


def _signer_for_signature(signature: str):
    """Override of docker_sign_verify.Signer::_for_signature()."""
    if "FAKE SIGNATURE" in signature:
        return FakeSigner()
    else:
        raise RuntimeError("Unsupported signature type!")


class FakeSigner(Signer):
    """Creates and verifies docker image signatures static strings."""

    def __init__(
        self,
        signature_value="-----BEGIN FAKE SIGNATURE-----\nDEFAULT FAKE SIGNATURE\n-----END FAKE SIGNATURE-----",
    ):
        self.signature_value = signature_value

    def sign(self, data: bytes) -> str:
        return self.signature_value

    def verify(self, data: bytes, signature: str):
        return {"type": "fake", "valid": True}
