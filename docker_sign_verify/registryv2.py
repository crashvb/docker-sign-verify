#!/usr/bin/env python

# pylint: disable=too-many-arguments
"""Classes that provide a source of docker images."""

import logging
import os

from functools import wraps
from typing import Any, Dict, List, NamedTuple, Optional, Union

from aiofiles.base import AiofilesContextManager
from aiotempfile.aiotempfile import open as aiotempfile
from docker_registry_client_async import (
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
    Manifest,
)
from docker_registry_client_async.typing import (
    DockerRegistryClientAsyncPutBlobUpload,
)
from docker_registry_client_async.utils import must_be_equal

from .exceptions import (
    DigestMismatchError,
    SignatureMismatchError,
    UnsupportedSignatureTypeError,
)
from .imageconfig import ImageConfig, SignatureTypes
from .registryv2manifest import RegistryV2Manifest
from .registryv2manifestlist import RegistryV2ManifestList
from .signer import Signer
from .utils import gunzip, xellipsis

LOGGER = logging.getLogger(__name__)


class RegistryV2VerifyImageIntegrity(NamedTuple):
    # pylint: disable=missing-class-docstring
    compressed_layer_files: Optional[List[AiofilesContextManager]]
    image_config: ImageConfig
    manifest: RegistryV2Manifest
    manifest_list: Optional[RegistryV2ManifestList]
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
    manifest: RegistryV2Manifest
    manifest_layers: List[FormattedSHA256]
    manifest_list: Optional[RegistryV2ManifestList]


class RegistryV2SignImage(NamedTuple):
    # pylint: disable=missing-class-docstring
    image_config: ImageConfig
    manifest_signed: RegistryV2Manifest
    signature_value: str
    verify_image_data: RegistryV2VerifyImageIntegrity


class RegistryV2VerifyImageSignatures(NamedTuple):
    # pylint: disable=missing-class-docstring
    compressed_layer_files: Optional[List[AiofilesContextManager]]
    image_config: ImageConfig
    manifest: RegistryV2Manifest
    manifest_list: Optional[RegistryV2ManifestList]
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
        architecture: str = PLATFORM_ARCHITECTURE,
        docker_registry_client_async: DockerRegistryClientAsync = None,
        dry_run: bool = False,
        operating_system: str = PLATFORM_OS,
        signer_kwargs: Dict[str, Dict] = None,
        **kwargs,
    ):
        # pylint: disable=unused-argument
        """
        Args:
            architecture: The name of the CPU architecture.
            atomic_signer: Signer used to create atomic signatures.
            docker_registry_client_async: The underlying DRCA instance.
            dry_run: If true, destination image sources will not be changed.
            operating_system: The name of the operating system.
            signer_kwargs: Parameters to be passed to the Signer instances when the are initialized.
        """
        self.architecture = architecture
        self.docker_registry_client_async = docker_registry_client_async
        self.dry_run = dry_run
        self.operating_system = operating_system
        self.signer_kwargs = signer_kwargs if signer_kwargs is not None else {}
        for key in ["dry_run", "signer_kwargs"]:
            kwargs.pop(key, None)
        if not self.docker_registry_client_async:
            self.docker_registry_client_async = DockerRegistryClientAsync(**kwargs)

    async def __aenter__(self) -> "RegistryV2":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self):
        """Gracefully closes this instance."""
        if self.docker_registry_client_async:
            await self.docker_registry_client_async.close()

    async def _get_manifest_from_manifest_list(
        self,
        *,
        check: bool = True,
        image_name: ImageName,
        manifest_list: RegistryV2ManifestList,
    ) -> RegistryV2Manifest:
        """
        Retrieves a manifest for a given architecture / os type from a given manifest list.

        Args:
            check: If true, sanity checks will be performed.
            image_name: The image name.
            manifest_list: The manifest list from which to retrieve the manifest.

        Returns:
            A the corresponding manifest.
        """
        result = []
        digests = manifest_list.get_manifests(
            architecture=self.architecture, operating_system=self.operating_system
        )
        for digest in digests:
            img_name = image_name.clone().set_digest(digest).set_tag()
            result.append(await self.get_manifest(image_name=img_name))
        if check:
            if not result:
                raise RuntimeError("Unable to resolve manifest from manifest list!")
            if len(result) > 1:
                LOGGER.warning("Ambiguous manifest list resolution!")
        return result[0]

    async def _verify_image_config(
        self, *, image_name: ImageName, **kwargs
    ) -> RegistryV2VerifyImageConfig:
        """
        Verifies the integration of an image configuration against metadata contained within a manifest.

        Args:
            image_name: The image name for which to retrieve the configuration.

        Returns:
            RegistryV2VerifyImageConfig:
                image_config: The image configuration.
                image_layers: The listing of image layer identifiers.
                manifest: The image-source specific manifest.
                manifest_layers: The listing of manifest layer identifiers.
                manifest_list: The image-source specific manifest list.
        """

        # Retrieve the image configuration digest and layers identifiers from the manifest ...
        LOGGER.debug("Verifying Integrity: %s ...", image_name.resolve_name())
        manifest = await self.get_manifest(image_name=image_name, **kwargs)
        manifest_list = None
        if isinstance(manifest, RegistryV2ManifestList):
            manifest_list = manifest
            LOGGER.debug(
                "    manifest list digest: %s", xellipsis(manifest_list.get_digest())
            )
            manifest = await self._get_manifest_from_manifest_list(
                image_name=image_name, manifest_list=manifest_list
            )

        LOGGER.debug("    manifest digest: %s", xellipsis(manifest.get_digest()))
        config_digest = manifest.get_config_digest()
        LOGGER.debug("    config digest: %s", xellipsis(config_digest))
        manifest_layers = manifest.get_layers()
        LOGGER.debug("    manifest layers:")
        for layer in manifest_layers:
            LOGGER.debug("        %s", xellipsis(layer))

        # Retrieve the image configuration ...
        image_config = await self.get_image_config(image_name=image_name, **kwargs)
        config_digest_canonical = image_config.get_digest_canonical()
        LOGGER.debug(
            "    config digest (canonical): %s", xellipsis(config_digest_canonical)
        )
        must_be_equal(
            actual=image_config.get_digest(),
            expected=config_digest,
            msg="Image config digest mismatch",
        )

        # Retrieve the image layers from the image configuration ...
        image_layers = image_config.get_image_layers()
        LOGGER.debug("    image layers:")
        for layer in image_layers:
            LOGGER.debug("        %s", xellipsis(layer))

        # Quick check: Ensure that the layer counts are consistent
        must_be_equal(
            actual=len(image_layers),
            expected=len(manifest_layers),
            msg="Layer count mismatch",
        )

        return RegistryV2VerifyImageConfig(
            image_config=image_config,
            image_layers=image_layers,
            manifest=manifest,
            manifest_layers=manifest_layers,
            manifest_list=manifest_list,
        )

    async def get_image_config(self, *, image_name: ImageName, **kwargs) -> ImageConfig:
        """
        Retrieves an image configuration (config.json).

        Args:
            image_name: The image name.

        Returns:
            The image configuration.
        """
        manifest = await self.get_manifest(image_name=image_name, **kwargs)
        if isinstance(manifest, RegistryV2ManifestList):
            manifest = await self._get_manifest_from_manifest_list(
                image_name=image_name, manifest_list=manifest
            )
        response = await self.docker_registry_client_async.get_blob(
            digest=manifest.get_config_digest(), image_name=image_name, **kwargs
        )
        return ImageConfig(config=response.blob)

    async def get_manifest(
        self, *, image_name: ImageName = None, **kwargs
    ) -> Union[Manifest, RegistryV2Manifest, RegistryV2ManifestList]:
        """
        Retrieves the manifest for a given image.

        Args:
            image_name: The name image for which to retrieve the manifest.

        Returns:
            The image source-specific manifest.
        """
        response = await self.docker_registry_client_async.get_manifest(
            image_name, **kwargs
        )
        manifest = response.manifest
        if RegistryV2Manifest.is_type(manifest):
            manifest = RegistryV2Manifest(manifest=manifest)
        elif RegistryV2ManifestList.is_type(manifest):
            manifest = RegistryV2ManifestList(manifest=manifest)

        return manifest

    @check_dry_run
    async def put_image(
        self,
        *,
        image_config: ImageConfig,
        image_name: ImageName,
        layer_files: List,
        manifest: RegistryV2Manifest,
        manifest_list: RegistryV2ManifestList = None,
        **kwargs,
    ):
        """
        Stores a given image (manifest, image_config, and layers) from another image source.

        Args:
            image_config: The image configuration to be stored.
            image_name: The name of the image being stored.
            layer_files: List of files from which to read the layer content, in source image source format.
            manifest: The image source-specific manifest to be stored, in source image source format.
            manifest_list: The image source-specific manifest list to be stored, in source image source format.
        """
        if manifest_list:
            # There doesn't appear to be a way to replicate manifest lists without replicating ALL manifests contained
            # within ...
            LOGGER.warning("Manifest list will not be replicated!")

        # Replicate all of the image layers ...
        LOGGER.debug("    Replicating image layers ...")
        manifest_layers = manifest.get_layers()
        for i, manifest_layer in enumerate(manifest_layers):
            await self.put_image_layer_from_disk(
                digest_expected=manifest_layer,
                file=layer_files[i],
                image_name=image_name,
                **kwargs,
            )

        # Replicate the image configuration ...
        LOGGER.debug("    Replicating image configuration ...")
        await self.put_image_config(
            image_config=image_config, image_name=image_name, **kwargs
        )

        # Replicate the manifest (always have to do this to assign tags) ...
        LOGGER.debug("    Replicating manifest ...")
        await self.docker_registry_client_async.put_manifest(
            image_name=image_name, manifest=manifest, **kwargs
        )

    @check_dry_run
    async def put_image_config(
        self, *, image_name: ImageName, image_config: ImageConfig, **kwargs
    ) -> Optional[DockerRegistryClientAsyncPutBlobUpload]:
        """
        Assigns an image configuration (config.json).

        Args:
            image_name: The image name.
            image_config: The image configuration to be assigned.
        """
        response = await self.docker_registry_client_async.head_blob(
            image_name=image_name, digest=image_config.get_digest()
        )
        if response.result:
            LOGGER.debug("        image configuration already exists.")
            return None

        response = await self.docker_registry_client_async.post_blob(
            image_name=image_name, **kwargs
        )
        digest = image_config.get_digest()
        response = await self.docker_registry_client_async.put_blob_upload(
            digest=digest,
            location=response.location,
            data=image_config.get_bytes(),
            **kwargs,
        )
        must_be_equal(
            actual=response.digest,
            error_type=DigestMismatchError,
            expected=digest,
            msg="Configuration digest mismatch",
        )
        return response

    @check_dry_run
    async def put_image_layer_from_disk(
        self,
        *,
        image_name: ImageName,
        digest_expected: FormattedSHA256 = None,
        file,
        **kwargs,
    ) -> Optional[DockerRegistryClientAsyncPutBlobUpload]:
        """
        Assigns a single image layer read from disk.

        Args:
            image_name: The image name.
            digest_expected: Expected layer digest.
            file: File from which to read the layer content.
        """
        if digest_expected:
            response = await self.docker_registry_client_async.head_blob(
                digest=digest_expected, image_name=image_name
            )
            if response.result:
                LOGGER.debug("        image layer already exists.")
                return None

        response = await self.docker_registry_client_async.post_blob(
            image_name=image_name, **kwargs
        )
        # Note: PATCH is needed to retrieve the digest of the local content, needed by POST
        response = await self.docker_registry_client_async.patch_blob_upload_from_disk(
            file=file, location=response.location, **kwargs
        )
        response = await self.docker_registry_client_async.put_blob_upload(
            digest=response.digest, location=response.location, **kwargs
        )
        if digest_expected:
            must_be_equal(
                actual=response.digest,
                error_type=DigestMismatchError,
                expected=digest_expected,
                msg="Layer digest mismatch",
            )
        return response

    async def sign_image(
        self,
        *,
        image_name_dest: ImageName,
        image_name_src: ImageName,
        signature_type: SignatureTypes = SignatureTypes.SIGN,
        signer: Signer,
        **kwargs,
    ) -> RegistryV2SignImage:
        """
        Retrieves, verifies and signs the image, storing it in the destination image source.

        Args:
            image_name_dest: The description image name.
            image_name_src: The source image name.
            signature_type: Specifies what type of signature action to perform.
            signer: The signer used to create the signature value.

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
            else "Resigning"
            if signature_type == SignatureTypes.RESIGN
            else "Signing (atomic)",
            image_name_src.resolve_name(),
        )

        image_name_dest = image_name_dest.clone()
        if image_name_dest.resolve_digest():
            image_name_dest.digest = None
            LOGGER.warning(
                "It is not possible to store a signed image to a predetermined digest! Adjusted destination: %s",
                image_name_dest.resolve_name(),
            )

        # Verify image integrity (we use the verified values from this point on)
        # Note: Callers to this method MUST invoke verify_image_data.close()!
        data = await self.verify_image_integrity(image_name=image_name_src, **kwargs)

        if data.manifest_list:
            LOGGER.warning(
                "It is not possible to sign a manifest list; only the resolved manifest will be signed!"
            )

        # Generate a signed image configuration ...
        signature_value = await data.image_config.sign(
            signature_type=signature_type, signer=signer
        )
        LOGGER.debug("    Signature:\n%s", signature_value)
        image_config = data.image_config
        config_digest = image_config.get_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest)

        # Generate a new registry manifest ...
        manifest = data.manifest.clone()
        manifest.set_config_digest(config_digest, len(image_config.get_bytes()))
        manifest_digest = manifest.get_digest()
        LOGGER.debug("    manifest digest (signed): %s", manifest_digest)

        await self.put_image(
            image_config=image_config,
            image_name=image_name_dest,
            layer_files=data.compressed_layer_files,
            manifest=manifest,
            manifest_list=data.manifest_list,
            **kwargs,
        )

        image_name_dest.digest = manifest.get_digest()

        if not self.dry_run:
            LOGGER.debug("Created new image: %s", image_name_dest.resolve_name())

        return RegistryV2SignImage(
            image_config=data.image_config,
            manifest_signed=manifest,
            signature_value=signature_value,
            verify_image_data=data,
        )

    async def verify_image_integrity(
        self, *, image_name: ImageName, **kwargs
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
                manifest: The image source-specific manifest file.
                manifest_list: The image-source specific manifest list.
                uncompressed_layer_files: The list of uncompressed layer files on disk.
        """
        data = await self._verify_image_config(image_name=image_name, **kwargs)

        # Reconcile manifest and manifest list ...
        if (
            data.manifest_list
            and not data.manifest.get_digest()
            in data.manifest_list.get_manifests(
                architecture=self.architecture, operating_system=self.operating_system
            )
        ):
            raise DigestMismatchError("Manifest not contained within manifest list!")

        # Reconcile manifest layers and image layers (in order)...
        compressed_layer_files = []
        uncompressed_layer_files = []
        try:
            for i, layer in enumerate(data.manifest_layers):
                # Retrieve the registry image layer and verify the digest ...
                compressed_layer_files.append(
                    await aiotempfile(prefix="tmp-compressed")
                )
                data_compressed = (
                    await self.docker_registry_client_async.get_blob_to_disk(
                        digest=layer,
                        file=compressed_layer_files[i],
                        image_name=image_name,
                        **kwargs,
                    )
                )
                must_be_equal(
                    actual=data_compressed.digest,
                    expected=layer,
                    msg=f"Registry layer[{i}] digest mismatch",
                )
                must_be_equal(
                    actual=data_compressed.size,
                    expected=os.path.getsize(compressed_layer_files[i].name),
                    msg=f"Registry layer[{i}] size mismatch",
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
                    actual=data_uncompressed.digest,
                    expected=data.image_layers[i],
                    msg=f"Image layer[{i}] digest mismatch",
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
            manifest_list=data.manifest_list,
            uncompressed_layer_files=uncompressed_layer_files,
        )

    async def verify_image_signatures(
        self, *, image_name: ImageName, **kwargs
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
                manifest: The image source-specific manifest file.
                manifest_list: The image-source specific manifest list.
                signatures: as defined by :func:~docker_sign_verify.ImageConfig.verify_signatures.
                uncompressed_layer_files: The list of uncompressed layer files on disk.
        """

        # Verify image integrity (we use the verified values from this point on)
        data = await self.verify_image_integrity(image_name=image_name, **kwargs)

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

            # List the image signatures ...
            LOGGER.debug("    signatures:")
            for result in signatures.results:
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
            data.close()
            raise

        LOGGER.debug("Signature check passed.")

        return RegistryV2VerifyImageSignatures(
            compressed_layer_files=data.compressed_layer_files,
            image_config=data.image_config,
            manifest=data.manifest,
            manifest_list=data.manifest_list,
            signatures=signatures,
            uncompressed_layer_files=data.uncompressed_layer_files,
        )
