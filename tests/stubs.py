#!/usr/bin/env python

"""Stub classes for offline testing."""

from docker_sign_verify import (
    FormattedSHA256,
    ImageConfig,
    ImageName,
    ImageSource,
    Manifest,
    RegistryV2Manifest,
    Signer,
)

from .testutils import get_test_data


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

    # Signer Members

    def sign(self, data: bytes) -> str:
        return self.signature_value

    def verify(self, data: bytes, signature: str):
        return {"type": "fake", "valid": True}


class FakeRegistryV2ImageSourceNoLabels(ImageSource):
    """Fake image source used to expose methods in the abstract base class."""

    def __init__(self, request, layer_exists: bool = True, **kwargs):
        super(FakeRegistryV2ImageSourceNoLabels, self).__init__(**kwargs)
        self.config = None
        self.does_layer_exists = layer_exists
        self.manifest = None
        self.request = request

    def quick_sign(self, image_name: ImageName) -> dict:
        """
        Signs a given image in an image source using a fake signer and returns the results.
        This method is a testing shortcut.

        Args:
            image_name: The name of the image to be signed.

        Returns:
            The results of the docker_sign_verify.ImageSource::_sign_image_config() method.
        """
        # pylint: disable=protected-access
        result = self._sign_image_config(FakeSigner(), image_name)

        self.config = result["image_config"]
        self.manifest.set_config_digest(
            result["image_config"].get_config_digest(),
            len(result["image_config"].get_config()),
        )
        return result

    # ImageSource Members

    def get_image_config(self, image_name: ImageName) -> ImageConfig:
        if not self.config:
            config = get_test_data(self.request, __name__, "stub_config.json")
            self.config = ImageConfig(config)
        return self.config

    def get_image_layer_to_disk(self, image_name: ImageName, layer: str, file):
        raise RuntimeError("Logic error; method should not be invoked!")

    def get_manifest(self, image_name: ImageName = None) -> Manifest:
        if not self.manifest:
            manifest = get_test_data(self.request, __name__, "stub_manifest.json")
            self.manifest = RegistryV2Manifest(manifest)
        return self.manifest

    def put_manifest(self, manifest: Manifest, image_name: ImageName = None):
        raise RuntimeError("Logic error; method should not be invoked!")

    def put_image_config(self, image_name: ImageName, image_config: ImageConfig):
        raise RuntimeError("Logic error; method should not be invoked!")

    def put_image_layer(self, image_name: ImageName, content):
        raise RuntimeError("Logic error; method should not be invoked!")

    def put_image_layer_from_disk(self, image_name: ImageName, file):
        raise RuntimeError("Logic error; method should not be invoked!")

    def layer_exists(self, image_name: ImageName, layer: FormattedSHA256) -> bool:
        return self.does_layer_exists

    def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source,
        dest_image_name: ImageName,
    ):
        raise RuntimeError("Logic error; method should not be invoked!")

    def unsign_image(
        self, src_image_name: ImageName, dest_image_source, dest_image_name: ImageName
    ):
        raise RuntimeError("Logic error; method should not be invoked!")

    def verify_image_integrity(self, image_name: ImageName):
        data = self._verify_image_config(image_name)

        # LGTM ...

        return {
            "compressed_layer_files": [],
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": [],
        }
