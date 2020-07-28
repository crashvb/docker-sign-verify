#!/usr/bin/env python

"""Stub classes for offline testing."""

import shlex
import sys

from typing import Dict, List

from click.testing import CliRunner, Result
from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import (
    ImageConfig,
    ImageSource,
    Manifest,
    RegistryV2Manifest,
    SignatureTypes,
    Signer,
)

from .testutils import get_test_data


class DSVCliRunner(CliRunner):
    """
    click.testing.CliRunner.invoke w/o isolation, as it breaks logging:
    https://github.com/pallets/click/issues/824
    """

    def invoke(self, cli, args=None, catch_exceptions=True, **extra) -> Result:
        # pylint: disable=arguments-differ
        exc_info = None
        exception = None
        exit_code = 0

        if isinstance(args, str):
            args = shlex.split(args)

        if "prog_name" not in extra:
            extra["prog_name"] = self.get_default_prog_name(cli)

        try:
            cli.main(args=args or (), **extra)
        except SystemExit as exc:
            exc_info = sys.exc_info()
            exit_code = exc.code
            if exit_code is None:
                exit_code = 0

            if exit_code != 0:
                exception = exc

            if not isinstance(exit_code, int):
                sys.stdout.write(str(exit_code))
                sys.stdout.write("\n")
                exit_code = 1

        except Exception as exc:  # pylint: disable=broad-except
            if not catch_exceptions:
                raise
            exc_info = sys.exc_info()
            exit_code = 1
            exception = exc

        return Result(
            runner=self,
            stdout_bytes=b"",
            stderr_bytes=b"",
            exit_code=exit_code,
            exception=exception,
            exc_info=exc_info,
        )


def _signer_for_signature(signature: str) -> Signer:
    """Override of docker_sign_verify.Signer::_for_signature()."""
    if "FAKE SIGNATURE" in signature:
        return FakeSigner()
    raise RuntimeError("Unsupported signature type!")


class FakeSigner(Signer):
    """Creates and verifies docker image signatures static strings."""

    def __init__(
        self,
        signature_value="-----BEGIN FAKE SIGNATURE-----\nDEFAULT FAKE SIGNATURE\n-----END FAKE SIGNATURE-----",
    ):
        self.signature_value = signature_value

    # Signer Members

    async def sign(self, data: bytes) -> str:
        return self.signature_value.format(data)

    async def verify(self, data: bytes, signature: str):
        return {"type": "fake", "valid": True}


class FakeRegistryV2ImageSourceNoLabels(ImageSource):
    """Fake image source used to expose methods in the abstract base class."""

    def __init__(self, request, layer_exists: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.config = None
        self.does_layer_exists = layer_exists
        self.manifest = None
        self.request = request

    async def quick_sign(self, image_name: ImageName) -> Dict:
        """
        Signs a given image in an image source using a fake signer and returns the results.
        This method is a testing shortcut.

        Args:
            image_name: The name of the image to be signed.

        Returns:
            The results of the docker_sign_verify.ImageSource::_sign_image_config() method.
        """
        # pylint: disable=protected-access
        result = await self._sign_image_config(
            FakeSigner(), image_name, SignatureTypes.SIGN
        )

        self.config = result["image_config"]
        self.manifest.set_config_digest(
            result["image_config"].get_digest(),
            len(result["image_config"].get_bytes()),
        )
        return result

    # ImageSource Members

    async def get_image_config(self, image_name: ImageName, **kwargs) -> ImageConfig:
        if not self.config:
            config = get_test_data(self.request, __name__, "stub_config.json")
            self.config = ImageConfig(config)
        return self.config

    async def get_image_layer_to_disk(
        self, image_name: ImageName, layer: str, file, **kwargs
    ):
        raise RuntimeError("Logic error; method should not be invoked!")

    async def get_manifest(self, image_name: ImageName = None, **kwargs) -> Manifest:
        if not self.manifest:
            manifest = get_test_data(self.request, __name__, "stub_manifest.json")
            self.manifest = RegistryV2Manifest(manifest)
        return self.manifest

    async def layer_exists(
        self, image_name: ImageName, layer: FormattedSHA256, **kwargs
    ) -> bool:
        return self.does_layer_exists

    async def put_image(
        self,
        image_source,
        image_name: ImageName,
        manifest: Manifest,
        image_config: ImageConfig,
        layer_files: List,
        **kwargs,
    ):
        raise RuntimeError("Logic error; method should not be invoked!")

    async def put_image_config(
        self, image_name: ImageName, image_config: ImageConfig, **kwargs
    ):
        raise RuntimeError("Logic error; method should not be invoked!")

    async def put_image_layer(self, image_name: ImageName, content, **kwargs):
        raise RuntimeError("Logic error; method should not be invoked!")

    async def put_image_layer_from_disk(self, image_name: ImageName, file, **kwargs):
        raise RuntimeError("Logic error; method should not be invoked!")

    async def put_manifest(
        self, manifest: Manifest, image_name: ImageName = None, **kwargs
    ):
        raise RuntimeError("Logic error; method should not be invoked!")

    async def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source,
        dest_image_name: ImageName,
        signature_type: SignatureTypes = SignatureTypes.SIGN,
        **kwargs,
    ):
        raise RuntimeError("Logic error; method should not be invoked!")

    async def verify_image_integrity(self, image_name: ImageName, **kwargs):
        data = await self._verify_image_config(image_name)

        # LGTM ...

        return {
            "compressed_layer_files": [],
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": [],
        }
