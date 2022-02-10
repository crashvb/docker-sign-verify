#!/usr/bin/env python

# pylint: disable=too-many-arguments
"""Classes that provide a source of docker images."""

import logging
import os

from functools import wraps
from typing import Any, Dict, List, NamedTuple, Optional

from aiofiles.base import AiofilesContextManager
from aiotempfile.aiotempfile import open as aiotempfile
from docker_registry_client_async import (
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
)
from docker_registry_client_async.typing import (
    DockerRegistryClientAsyncPutBlobUpload,
    DockerRegistryClientAsyncPutManifest,
)
from docker_registry_client_async.utils import must_be_equal

from .exceptions import SignatureMismatchError, UnsupportedSignatureTypeError
from .imageconfig import ImageConfig, SignatureTypes
from .manifest import Manifest
from .registryv2manifest import RegistryV2Manifest
from .signer import Signer
from .utils import gunzip, xellipsis

LOGGER = logging.getLogger(__name__)


class RegistryV2VerifyImageIntegrity(NamedTuple):
    # pylint: disable=missing-class-docstring
    compressed_layer_files: Optional[List[AiofilesContextManager]]
    image_config: ImageConfig
    manifest: Manifest
    uncompressed_layer_files: List[AiofilesContextManager]

    def close(self):
        """Cleanup temporary files."""
        for file in self.compressed_layer_files + self.uncompressed_layer_files:
            file.close()


class RegistryV2SignImageConfig(NamedTuple):
    # pylint: disable=missing-class-docstring
    image_config: ImageConfig
    signature_value: str
    verify_image_data: RegistryV2VerifyImageIntegrity


class RegistryV2VerifyImageConfig(NamedTuple):
    # pylint: disable=missing-class-docstring
    image_config: ImageConfig
    image_layers: List[FormattedSHA256]
    manifest: Manifest
    manifest_layers: List[FormattedSHA256]


class RegistryV2GetImageLayerToDisk(NamedTuple):
    # pylint: disable=missing-class-docstring
    digest: FormattedSHA256
    size: int


class RegistryV2SignImage(NamedTuple):
    # pylint: disable=missing-class-docstring
    image_config: ImageConfig
    manifest_signed: Manifest
    signature_value: str
    verify_image_data: RegistryV2VerifyImageIntegrity


class RegistryV2VerifyImageSignatures(NamedTuple):
    # pylint: disable=missing-class-docstring
    compressed_layer_files: Optional[List[AiofilesContextManager]]
    image_config: ImageConfig
    manifest: Manifest
    signatures: Any
    uncompressed_layer_files: List[AiofilesContextManager]

    def close(self):
        """Cleanup temporary files."""
        for file in self.compressed_layer_files + self.uncompressed_layer_files:
            file.close()


def check_dry_run(func):
    """Validates the state of RegistryV2.dry_run before invoking the wrapped method."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        if args[0].dry_run:
            LOGGER.debug("Dry Run: skipping %s", func)
        else:
            return await func(*args, **kwargs)

    return wrapper


class RegistryV2:
    """
    Docker registry image source.
    """

    PLATFORM_ARCHITECTURE = os.environ.get("DSV_ARCHITECTURE", "amd64")
    PLATFORM_OS = os.environ.get("DSV_OPERATING_SYSTEM", "linux")

    def __init__(
        self,
        *,
        docker_registry_client_async: DockerRegistryClientAsync = None,
        dry_run: bool = False,
        signer_kwargs: Dict[str, Dict] = None,
        **kwargs,
    ):
        # pylint: disable=unused-argument
        """
        Args:
            docker_registry_client_async: The underlying DRCA instance.
            dry_run: If true, destination image sources will not be changed.
            signer_kwargs: Parameters to be passed to the Signer instances when the are initialized.
        """
        self.dry_run = dry_run
        self.signer_kwargs = signer_kwargs
        if self.signer_kwargs is None:
            self.signer_kwargs = {}
        for key in ["dry_run", "signer_kwargs"]:
            kwargs.pop(key, None)
        if not docker_registry_client_async:
            docker_registry_client_async = DockerRegistryClientAsync(**kwargs)
        self.docker_registry_client_async = docker_registry_client_async

    async def __aenter__(self) -> "RegistryV2":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self):
        """Gracefully closes this instance."""
        if self.docker_registry_client_async:
            await self.docker_registry_client_async.close()

    async def _sign_image_config(
        self,
        signer: Signer,
        image_name: ImageName,
        signature_type: SignatureTypes,
        **kwargs,
    ) -> RegistryV2SignImageConfig:
        """
        Verifies an image, then signs it without storing it in the image source.

        Args:
            signer: The signer used to create the signature value.
            image_name: The image name.
            signature_type: Specifies what type of signature action to perform.

        Returns:
            NamedTuple:
                image_config: The ImageConfig object corresponding to the signed image.
                signature_value: as defined by :func:~docker_sign_verify.ImageConfig.sign.
                verify_image_data: as defined by :func:~docker_sign_verify.RegistryV2.verify_image_integrity.
        """
        # Verify image integrity (we use the verified values from this point on)
        data = await self.verify_image_integrity(image_name, **kwargs)

        # Perform the desired signing operation
        try:
            signature_value = await data.image_config.sign(signer, signature_type)
        except Exception:
            for file in data.compressed_layer_files + data.uncompressed_layer_files:
                file.close()
            raise

        return RegistryV2SignImageConfig(
            image_config=data.image_config,
            signature_value=signature_value,
            verify_image_data=data,
        )

    async def _verify_image_config(
        self, image_name: ImageName, **kwargs
    ) -> RegistryV2VerifyImageConfig:
        """
        Verifies the integration of an image configuration against metadata contained within a manifest.

        Args:
            image_name: The image name for which to retrieve the configuration.

        Returns:
            NamedTuple:
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

        return RegistryV2VerifyImageConfig(
            image_config=image_config,
            image_layers=image_layers,
            manifest=manifest,
            manifest_layers=manifest_layers,
        )

    async def get_image_config(self, image_name: ImageName, **kwargs) -> ImageConfig:
        """
        Retrieves an image configuration (config.json).

        Args:
            image_name: The image name.

        Returns:
            The image configuration.
        """
        manifest = await self.get_manifest(image_name, **kwargs)
        config_digest = manifest.get_config_digest()
        response = await self.docker_registry_client_async.get_blob(
            image_name, config_digest, **kwargs
        )
        return ImageConfig(response.blob)

    async def get_image_layer_to_disk(
        self, image_name: ImageName, layer: FormattedSHA256, file, **kwargs
    ) -> RegistryV2GetImageLayerToDisk:
        """
        Retrieves a single image layer stored to disk.

        Args:
            image_name: The image name.
            layer: The layer identifier in the form: <hash type>:<digest value>.
            file: File in which to store the image layer.
        """
        response = await self.docker_registry_client_async.get_blob_to_disk(
            image_name, layer, file, **kwargs
        )
        return RegistryV2GetImageLayerToDisk(digest=response.digest, size=response.size)

    async def get_manifest(
        self, image_name: ImageName = None, **kwargs
    ) -> RegistryV2Manifest:
        """
        Retrieves the manifest for a given image.

        Args:
            image_name: The name image for which to retrieve the manifest.

        Returns:
            The image source-specific manifest.
        """
        # FIXME: How do we handle manifest lists?
        response = await self.docker_registry_client_async.get_manifest(
            image_name, **kwargs
        )
        manifest = RegistryV2Manifest.new_from(response.manifest)
        return manifest

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
        response = await self.docker_registry_client_async.head_blob(
            image_name, layer, **kwargs
        )
        return response.result

    @check_dry_run
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
        # Replicate all of the image layers ...
        LOGGER.debug("    Replicating image layers ...")
        manifest_layers = manifest.get_layers()
        for i, manifest_layer in enumerate(manifest_layers):
            if not await self.layer_exists(image_name, manifest_layer, **kwargs):
                if isinstance(image_source, RegistryV2):
                    await self.put_image_layer_from_disk(
                        image_name, layer_files[i], **kwargs
                    )
                else:
                    raise NotImplementedError(
                        f"Translation from '{type(image_source)}' to '{type(self)}' is not supported!"
                    )

        # Replicate the image configuration ...
        LOGGER.debug("    Replicating image configuration ...")
        await self.put_image_config(image_name, image_config, **kwargs)

        # Replicate the manifest ...
        LOGGER.debug("    Replicating image manifest ...")
        if isinstance(image_source, RegistryV2):
            await self.put_manifest(manifest, image_name, **kwargs)
        else:
            raise NotImplementedError(
                f"Translation from '{type(image_source)}' to '{type(self)}' is not supported!"
            )

    @check_dry_run
    async def put_image_config(
        self, image_name: ImageName, image_config: ImageConfig, **kwargs
    ):
        """
        Assigns an image configuration (config.json).

        Args:
            image_name: The image name.
            image_config: The image configuration to be assigned.
        """
        if not await self.layer_exists(image_name, image_config.get_digest(), **kwargs):
            return await self.put_image_layer(
                image_name, image_config.get_bytes(), **kwargs
            )

    @check_dry_run
    async def put_image_layer(
        self, image_name: ImageName, content, **kwargs
    ) -> DockerRegistryClientAsyncPutBlobUpload:
        """
        Assigns a single image layer.

        Args:
            image_name: The image name.
            content: The layer content.
        """
        response = await self.docker_registry_client_async.post_blob(
            image_name, **kwargs
        )
        digest = FormattedSHA256.calculate(content)
        return await self.docker_registry_client_async.put_blob_upload(
            response.location, digest, data=content, **kwargs
        )
        # TODO: Should we check self.layer_exists(image_name, digest) here, like docker CLI does?

    @check_dry_run
    async def put_image_layer_from_disk(
        self, image_name: ImageName, file, **kwargs
    ) -> DockerRegistryClientAsyncPutBlobUpload:
        """
        Assigns a single image layer read from disk.

        Args:
            image_name: The image name.
            file: File from which to read the layer content.
        """
        response = await self.docker_registry_client_async.post_blob(
            image_name, **kwargs
        )
        # Note: PATCH is needed to retrieve the digest of the local content, needed by POST
        response = await self.docker_registry_client_async.patch_blob_upload_from_disk(
            response.location, file, **kwargs
        )
        return await self.docker_registry_client_async.put_blob_upload(
            response.location, response.digest, **kwargs
        )
        # TODO: Should we check self.layer_exists(image_name, digest) here, like docker CLI does?

    @check_dry_run
    async def put_manifest(
        self, manifest: Manifest, image_name: ImageName = None, **kwargs
    ) -> DockerRegistryClientAsyncPutManifest:
        """
        Assigns the manifest for a given image.

        Args:
            manifest: The image source-specific manifest to be assigned.
            image_name: The name of the image for which to assign the manifest.
        """
        return await self.docker_registry_client_async.put_manifest(
            image_name, manifest, **kwargs
        )

    async def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source: "RegistryV2",
        dest_image_name: ImageName,
        signature_type: SignatureTypes = SignatureTypes.SIGN,
        **kwargs,
    ) -> RegistryV2SignImage:
        """
        Retrieves, verifies and signs the image, storing it in the destination image source.

        Args:
            signer: The signer used to create the signature value.
            src_image_name: The source image name.
            dest_image_source: The destination image source into which to store the signed image.
            dest_image_name: The description image name.
            signature_type: Specifies what type of signature action to perform.

        Returns:
            NamedTuple:
                image_config: The ImageConfig object corresponding to the signed image.
                signature_value: as defined by :func:~docker_sign_verify.ImageConfig.sign.
                verify_image_data: as defined by :func:~docker_sign_verify.ImageSource.verify_image_integrity.
                manifest_signed: The signed image source-specific manifest.
        """
        LOGGER.debug(
            "%s: %s ...",
            "Endorsing"
            if signature_type == SignatureTypes.ENDORSE
            else "Signing"
            if signature_type == SignatureTypes.SIGN
            else "Resigning",
            src_image_name.resolve_name(),
        )

        dest_image_name = dest_image_name.clone()
        if dest_image_name.resolve_digest():
            dest_image_name.digest = None
            LOGGER.warning(
                "It is not possible to store a signed image to a predetermined digest! Adjusted destination: %s",
                dest_image_name.resolve_name(),
            )

        # Generate a signed image configuration ...
        data = await self._sign_image_config(
            signer, src_image_name, signature_type, **kwargs
        )
        LOGGER.debug("    Signature:\n%s", data.signature_value)
        image_config = data.image_config
        config_digest = image_config.get_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest)

        # Generate a new registry manifest ...
        manifest = data.verify_image_data.manifest.clone()
        manifest.set_config_digest(config_digest, len(image_config.get_bytes()))
        data = RegistryV2SignImage(
            image_config=data.image_config,
            manifest_signed=manifest,
            signature_value=data.signature_value,
            verify_image_data=data.verify_image_data,
        )

        await dest_image_source.put_image(
            self,
            dest_image_name,
            manifest,
            image_config,
            data.verify_image_data.compressed_layer_files,
            **kwargs,
        )

        dest_image_name.digest = manifest.get_digest()

        if not self.dry_run:
            LOGGER.debug("Created new image: %s", dest_image_name.resolve_name())

        return data

    async def verify_image_integrity(
        self, image_name: ImageName, **kwargs
    ) -> RegistryV2VerifyImageIntegrity:
        """
        Verifies that the image source data format is consistent with respect to the image configuration and image
        layers, and that the image configuration and image layers are internally consistent (the digest values match).

        Args:
            image_name: The image name.

        Returns:
            NamedTuple:
                compressed_layer_files: The list of compressed layer files on disk (optional).
                image config: The image configuration.
                manifest: The image source-specific manifest file (archive, registry, repository).
                uncompressed_layer_files: The list of uncompressed layer files on disk.
        """
        data = await self._verify_image_config(image_name, **kwargs)

        # Reconcile manifest layers and image layers (in order)...
        compressed_layer_files = []
        uncompressed_layer_files = []
        try:
            for i, layer in enumerate(data.manifest_layers):
                # Retrieve the registry image layer and verify the digest ...
                compressed_layer_files.append(
                    await aiotempfile(prefix="tmp-compressed")
                )
                data_compressed = await self.get_image_layer_to_disk(
                    image_name, layer, compressed_layer_files[i], **kwargs
                )
                must_be_equal(
                    layer,
                    data_compressed.digest,
                    f"Registry layer[{i}] digest mismatch",
                )
                must_be_equal(
                    os.path.getsize(compressed_layer_files[i].name),
                    data_compressed.size,
                    f"Registry layer[{i}] size mismatch",
                )

                # Decompress (convert) the registry image layer into the image layer
                # and verify the digest ...
                uncompressed_layer_files.append(
                    await aiotempfile(prefix="tmp-uncompressed")
                )
                data_uncompressed = await gunzip(
                    compressed_layer_files[i].name, uncompressed_layer_files[i]
                )
                must_be_equal(
                    data.image_layers[i],
                    data_uncompressed.digest,
                    f"Image layer[{i}] digest mismatch",
                )
        except Exception:
            for file in compressed_layer_files + uncompressed_layer_files:
                file.close()
            raise

        LOGGER.debug("Integrity check passed.")

        return RegistryV2VerifyImageIntegrity(
            compressed_layer_files=compressed_layer_files,
            image_config=data.image_config,
            manifest=data.manifest,
            uncompressed_layer_files=uncompressed_layer_files,
        )

    async def verify_image_signatures(
        self, image_name: ImageName, **kwargs
    ) -> RegistryV2VerifyImageSignatures:
        """
        Verifies that signatures contained within the image source data format are valid (that the image has not been
        modified since they were created)

        Args:
            image_name: The image name.

        Returns:
            NamedTuple:
                compressed_layer_files: The list of compressed layer files on disk (optional).
                image config: The image configuration.
                manifest: The image source-specific manifest file (archive, registry, repository).
                signatures: as defined by :func:~docker_sign_verify.ImageConfig.verify_signatures.
                uncompressed_layer_files: The list of uncompressed layer files on disk.
        """

        # Verify image integrity (we use the verified values from this point on)
        data = await self.verify_image_integrity(image_name, **kwargs)

        # Verify image signatures ...
        try:
            LOGGER.debug("Verifying Signature(s): %s ...", image_name.resolve_name())
            LOGGER.debug(
                "    config digest (signed): %s",
                xellipsis(data.image_config.get_digest()),
            )
            signatures = await data.image_config.verify_signatures(
                signer_kwargs=self.signer_kwargs
            )
            data = RegistryV2VerifyImageSignatures(
                compressed_layer_files=data.compressed_layer_files,
                image_config=data.image_config,
                manifest=data.manifest,
                signatures=signatures,
                uncompressed_layer_files=data.uncompressed_layer_files,
            )

            # List the image signatures ...
            LOGGER.debug("    signatures:")
            for result in data.signatures.results:
                if not hasattr(result, "valid"):
                    raise UnsupportedSignatureTypeError(
                        f"Unsupported signature type: {type(result)}!"
                    )

                if hasattr(result, "signer_short") and hasattr(result, "signer_long"):
                    if not result.valid:
                        raise SignatureMismatchError(
                            f"Verification failed for signature; {result.signer_short}"
                        )

                    for line in result.signer_long.splitlines():
                        LOGGER.debug(line)
                # Try to be friendly ...
                else:
                    if not result.valid:
                        raise SignatureMismatchError(
                            f"Verification failed for signature; unknown type: {type(result)}!"
                        )
                    LOGGER.debug("        Signature of unknown type: %s", type(result))
        except Exception:
            for file in data.compressed_layer_files + data.uncompressed_layer_files:
                file.close()
            raise

        LOGGER.debug("Signature check passed.")

        return data
