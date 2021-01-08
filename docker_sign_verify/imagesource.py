#!/usr/bin/env python

"""Classes that provide a source of docker images."""

import abc
import logging
import time

from functools import wraps
from typing import Any, cast, List, Optional, TypedDict

import gnupg  # Needed for type checking

from aiofiles.base import AiofilesContextManager
from docker_registry_client_async import FormattedSHA256, ImageName
from docker_registry_client_async.utils import must_be_equal

from .exceptions import SignatureMismatchError
from .imageconfig import ImageConfig, SignatureTypes
from .manifest import Manifest
from .signer import Signer
from .utils import UtilChunkFile, xellipsis

LOGGER = logging.getLogger(__name__)


class ImageSourceVerifyImageIntegrity(TypedDict):
    # pylint: disable=missing-class-docstring
    compressed_layer_files: Optional[List[AiofilesContextManager]]
    image_config: ImageConfig
    manifest: Manifest
    uncompressed_layer_files: List[AiofilesContextManager]


class ImageSourceSignImageConfig(TypedDict):
    # pylint: disable=missing-class-docstring
    image_config: ImageConfig
    signature_value: str
    verify_image_data: ImageSourceVerifyImageIntegrity


class ImageSourceVerifyImageConfig(TypedDict):
    # pylint: disable=missing-class-docstring
    image_config: ImageConfig
    image_layers: List[FormattedSHA256]
    manifest: Manifest
    manifest_layers: List[FormattedSHA256]


class ImageSourceGetImageLayerToDisk(UtilChunkFile):
    # pylint: disable=missing-class-docstring
    pass


class ImageSourceSignImage(ImageSourceSignImageConfig):
    # pylint: disable=missing-class-docstring
    manifest_signed: Manifest


class ImageSourceVerifyImageSignatures(ImageSourceVerifyImageIntegrity):
    # pylint: disable=missing-class-docstring
    signatures: Any


class ImageSource(abc.ABC):
    """
    Abstract source of docker images.
    """

    def __init__(self, *, dry_run: bool = False, **kwargs):
        """
        Args:
            dry_run: If true, destination image sources will not be changed.
        """
        self.dry_run = dry_run

    @staticmethod
    def check_dry_run(func):
        """Validates the state of ImageSource.dry_run before invoking the wrapped method."""

        @wraps(func)
        async def wrapper(*args, **kwargs):
            if args[0].dry_run:
                LOGGER.debug("Dry Run: skipping %s", func)
            else:
                return await func(*args, **kwargs)

        return wrapper

    async def _sign_image_config(
        self,
        signer: Signer,
        image_name: ImageName,
        signature_type: SignatureTypes,
        **kwargs,
    ) -> ImageSourceSignImageConfig:
        """
        Verifies an image, then signs it without storing it in the image source.

        Args:
            signer: The signer used to create the signature value.
            image_name: The image name.
            signature_type: Specifies what type of signature action to perform.

        Returns:
            dict:
                image_config: The ImageConfig object corresponding to the signed image.
                signature_value: as defined by :func:~docker_sign_verify.ImageConfig.sign.
                verify_image_data: as defined by :func:~docker_sign_verify.ImageSource.verify_image_integrity.
        """
        # Verify image integrity (we use the verified values from this point on)
        data = await self.verify_image_integrity(image_name, **kwargs)
        image_config = data["image_config"]

        # Perform the desired signing operation
        signature_value = await image_config.sign(signer, signature_type)

        return {
            "image_config": image_config,
            "signature_value": signature_value,
            "verify_image_data": data,
        }

    async def _verify_image_config(
        self, image_name: ImageName, **kwargs
    ) -> ImageSourceVerifyImageConfig:
        """
        Verifies the integration of an image configuration against metadata contained within a manifest.

        Args:
            image_name: The image name for which to retrieve the configuration.

        Returns:
            dict:
                image_config: The image configuration.
                image_layers: The listing of image layer identifiers.
                manifest: The image-source specific manifest.
                manifest_layers: The listing of manifest layer identifiers.
        """

        # Retrieve the image configuration digest and layers identifiers from the manifest ...
        LOGGER.debug("Verifying Integrity: %s ...", image_name.resolve_name())
        manifest = await self.get_manifest(image_name, **kwargs)
        LOGGER.debug("    manifest digest: %s", xellipsis(manifest.get_digest()))
        config_digest = manifest.get_config_digest(image_name)
        LOGGER.debug("    config digest: %s", xellipsis(config_digest))
        manifest_layers = manifest.get_layers(image_name)
        LOGGER.debug("    manifest layers:")
        for layer in manifest_layers:
            LOGGER.debug("        %s", xellipsis(layer))

        # Retrieve the image configuration ...
        image_config = await self.get_image_config(image_name, **kwargs)
        config_digest_canonical = image_config.get_digest_canonical()
        LOGGER.debug(
            "    config digest (canonical): %s", xellipsis(config_digest_canonical)
        )
        must_be_equal(
            config_digest,
            image_config.get_digest(),
            "Image config digest mismatch",
        )

        # Retrieve the image layers from the image configuration ...
        image_layers = image_config.get_image_layers()
        LOGGER.debug("    image layers:")
        for layer in image_layers:
            LOGGER.debug("        %s", xellipsis(layer))

        # Quick check: Ensure that the layer counts are consistent
        must_be_equal(len(manifest_layers), len(image_layers), "Layer count mismatch")

        return {
            "image_config": image_config,
            "image_layers": image_layers,
            "manifest": manifest,
            "manifest_layers": manifest_layers,
        }

    @abc.abstractmethod
    async def get_image_config(self, image_name: ImageName, **kwargs) -> ImageConfig:
        """
        Retrieves an image configuration (config.json).

        Args:
            image_name: The image name.

        Returns:
            The image configuration.
        """

    @abc.abstractmethod
    async def get_image_layer_to_disk(
        self, image_name: ImageName, layer: FormattedSHA256, file, **kwargs
    ) -> ImageSourceGetImageLayerToDisk:
        """
        Retrieves a single image layer stored to disk.

        Args:
            image_name: The image name.
            layer: The layer identifier in the form: <hash type>:<digest value>.
            file: File in which to store the image layer.
        """

    @abc.abstractmethod
    async def get_manifest(self, image_name: ImageName = None, **kwargs) -> Manifest:
        """
        Retrieves the manifest for a given image.

        Args:
            image_name: The name image for which to retrieve the manifest.

        Returns:
            The image source-specific manifest.
        """

    @abc.abstractmethod
    async def layer_exists(
        self, image_name: ImageName, layer: FormattedSHA256, **kwargs
    ) -> bool:
        """
        Checks if a given image layer exists.

        Args:
            image_name: The image name.
            layer: The layer identifier in the form: <hash type>:<digest value>.

        Returns:
            bool: True if the layer exists, False otherwise.
        """

    @abc.abstractmethod
    async def put_image(
        self,
        image_source,
        image_name: ImageName,
        manifest: Manifest,
        image_config: ImageConfig,
        layer_files: List,
        **kwargs,
    ):
        """
        Stores a given image (manifest, image_config, and layers) from another image source.

        Args:
            image_source: The source image source.
            image_name: The name of the image being stored.
            manifest: The image source-specific manifest to be stored, in source image source format.
            image_config: The image configuration to be stored.
            layer_files: List of files from which to read the layer content, in source image source format.
        """

    @abc.abstractmethod
    async def put_image_config(
        self, image_name: ImageName, image_config: ImageConfig, **kwargs
    ):
        """
        Assigns an image configuration (config.json).

        Args:
            image_name: The image name.
            image_config: The image configuration to be assigned.
        """

    @abc.abstractmethod
    async def put_image_layer(self, image_name: ImageName, content, **kwargs):
        """
        Assigns a single image layer.

        Args:
            image_name: The image name.
            content: The layer content.
        """

    @abc.abstractmethod
    async def put_image_layer_from_disk(self, image_name: ImageName, file, **kwargs):
        """
        Assigns a single image layer read from disk.

        Args:
            image_name: The image name.
            file: File from which to read the layer content.
        """

    @abc.abstractmethod
    async def put_manifest(
        self, manifest: Manifest, image_name: ImageName = None, **kwargs
    ):
        """
        Assigns the manifest for a given image.

        Args:
            manifest: The image source-specific manifest to be assigned.
            image_name: The name of the image for which to assign the manifest.
        """

    @abc.abstractmethod
    async def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source,
        dest_image_name: ImageName,
        signature_type: SignatureTypes = SignatureTypes.SIGN,
        **kwargs,
    ) -> ImageSourceSignImage:
        """
        Retrieves, verifies and signs the image, storing it in the destination image source.

        Args:
            signer: The signer used to create the signature value.
            src_image_name: The source image name.
            dest_image_source: The destination image source into which to store the signed image.
            dest_image_name: The description image name.
            signature_type: Specifies what type of signature action to perform.

        Returns:
            dict:
                image_config: The ImageConfig object corresponding to the signed image.
                signature_value: as defined by :func:~docker_sign_verify.ImageConfig.sign.
                verify_image_data: as defined by :func:~docker_sign_verify.ImageSource.verify_image_integrity.
                manifest_signed: The signed image source-specific manifest.
        """

    @abc.abstractmethod
    async def verify_image_integrity(
        self, image_name: ImageName, **kwargs
    ) -> ImageSourceVerifyImageIntegrity:
        """
        Verifies that the image source data format is consistent with respect to the image configuration and image
        layers, and that the image configuration and image layers are internally consistent (the digest values match).

        Args:
            image_name: The image name.

        Returns:
            dict:
                compressed_layer_files: The list of compressed layer files on disk (optional).
                image config: The image configuration.
                manifest: The image source-specific manifest file (archive, registry, repository).
                uncompressed_layer_files: The list of uncompressed layer files on disk.
        """

    async def verify_image_signatures(
        self, image_name: ImageName, **kwargs
    ) -> ImageSourceVerifyImageSignatures:
        """
        Verifies that signatures contained within the image source data format are valid (that the image has not been
        modified since they were created)

        Args:
            image_name: The image name.

        Returns:
            dict:
                compressed_layer_files: The list of compressed layer files on disk (optional).
                image config: The image configuration.
                manifest: The image source-specific manifest file (archive, registry, repository).
                signatures: as defined by :func:~docker_sign_verify.ImageConfig.verify_signatures.
                uncompressed_layer_files: The list of uncompressed layer files on disk.
        """

        # Verify image integrity (we use the verified values from this point on)
        integrity_data = await self.verify_image_integrity(image_name, **kwargs)

        # Verify image signatures ...
        LOGGER.debug("Verifying Signature(s): %s ...", image_name.resolve_name())
        LOGGER.debug(
            "    config digest (signed): %s",
            xellipsis(integrity_data["image_config"].get_digest()),
        )
        integrity_data = cast(ImageSourceVerifyImageSignatures, integrity_data)
        integrity_data["signatures"] = await integrity_data[
            "image_config"
        ].verify_signatures()

        # List the image signatures ...
        LOGGER.debug("    signatures:")
        for result in integrity_data["signatures"]["results"]:
            # pylint: disable=protected-access
            if isinstance(result, gnupg._parsers.Verify):
                if not result.valid:
                    raise SignatureMismatchError(
                        "Verification failed for signature with keyid '{0}': {1}".format(
                            result.key_id, result.status
                        )
                    )
                LOGGER.debug(
                    "        Signature made %s using key ID %s",
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.gmtime(float(result.sig_timestamp))
                    ),
                    result.key_id,
                )
                LOGGER.debug("            %s", result.username)
            elif result.get("type", None) == "pki":
                if not result["valid"]:
                    raise SignatureMismatchError(
                        "Verification failed for signature using cert: {0}".format(
                            result["keypair_path"]
                        )
                    )
                # TODO: Add better debug logging
                LOGGER.debug("        Signature made using undetailed PKI keypair.")
            else:
                LOGGER.error("Unknown Signature Type: %s", type(result))

        LOGGER.debug("Signature check passed.")

        return integrity_data
