#!/usr/bin/env python

"""Classes that provide a source of docker images."""

import logging
import os

from typing import cast, List

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

from .aiotempfile import open as aiotempfile
from .imageconfig import ImageConfig, SignatureTypes
from .imagesource import (
    ImageSource,
    ImageSourceGetImageLayerToDisk,
    ImageSourceSignImage,
    ImageSourceVerifyImageIntegrity,
)
from .manifest import Manifest
from .registryv2manifest import RegistryV2Manifest
from .signer import Signer
from .utils import gunzip

LOGGER = logging.getLogger(__name__)


class RegistryV2ImageSource(ImageSource):
    """
    Docker registry image source.
    """

    PLATFORM_ARCHITECTURE = os.environ.get("DSV_ARCHITECTURE", "amd64")
    PLATFORM_OS = os.environ.get("DSV_OPERATING_SYSTEM", "linux")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        kwargs.pop("dry_run", None)
        self.docker_registry_client_async = DockerRegistryClientAsync(**kwargs)

    async def __aenter__(self) -> "RegistryV2ImageSource":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self):
        """Gracefully closes this instance."""
        if self.docker_registry_client_async:
            await self.docker_registry_client_async.close()

    # ImageSource Members

    async def get_image_config(self, image_name: ImageName, **kwargs) -> ImageConfig:
        manifest = await self.get_manifest(image_name, **kwargs)
        config_digest = manifest.get_config_digest()
        response = await self.docker_registry_client_async.get_blob(
            image_name, config_digest, **kwargs
        )
        return ImageConfig(response["blob"])

    async def get_image_layer_to_disk(
        self, image_name: ImageName, layer: FormattedSHA256, file, **kwargs
    ) -> ImageSourceGetImageLayerToDisk:
        return await self.docker_registry_client_async.get_blob_to_disk(
            image_name, layer, file, **kwargs
        )

    async def get_manifest(
        self, image_name: ImageName = None, **kwargs
    ) -> RegistryV2Manifest:
        # FIXME: How do we handle manifest lists?
        response = await self.docker_registry_client_async.get_manifest(
            image_name, **kwargs
        )
        manifest = RegistryV2Manifest.new_from(response["manifest"])
        return manifest

    async def layer_exists(
        self, image_name: ImageName, layer: FormattedSHA256, **kwargs
    ) -> bool:
        response = await self.docker_registry_client_async.head_blob(
            image_name, layer, **kwargs
        )
        return response["result"]

    @ImageSource.check_dry_run
    async def put_image(
        self,
        image_source,
        image_name: ImageName,
        manifest: Manifest,
        image_config: ImageConfig,
        layer_files: List,
        **kwargs,
    ):
        # Replicate all of the image layers ...
        LOGGER.debug("    Replicating image layers ...")
        manifest_layers = manifest.get_layers()
        for i, manifest_layer in enumerate(manifest_layers):
            if not await self.layer_exists(image_name, manifest_layer, **kwargs):
                if isinstance(image_source, RegistryV2ImageSource):
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
        if isinstance(image_source, RegistryV2ImageSource):
            await self.put_manifest(manifest, image_name, **kwargs)
        else:
            raise NotImplementedError(
                f"Translation from '{type(image_source)}' to '{type(self)}' is not supported!"
            )

    @ImageSource.check_dry_run
    async def put_image_config(
        self, image_name: ImageName, image_config: ImageConfig, **kwargs
    ):
        if not await self.layer_exists(image_name, image_config.get_digest(), **kwargs):
            return await self.put_image_layer(
                image_name, image_config.get_bytes(), **kwargs
            )

    @ImageSource.check_dry_run
    async def put_image_layer(
        self, image_name: ImageName, content, **kwargs
    ) -> DockerRegistryClientAsyncPutBlobUpload:
        response = await self.docker_registry_client_async.post_blob(
            image_name, **kwargs
        )
        digest = FormattedSHA256.calculate(content)
        return await self.docker_registry_client_async.put_blob_upload(
            response["location"], digest, data=content, **kwargs
        )
        # TODO: Should we check self.layer_exists(image_name, digest) here, like docker CLI does?

    @ImageSource.check_dry_run
    async def put_image_layer_from_disk(
        self, image_name: ImageName, file, **kwargs
    ) -> DockerRegistryClientAsyncPutBlobUpload:
        response = await self.docker_registry_client_async.post_blob(
            image_name, **kwargs
        )
        # Note: PATCH is needed to retrieve the digest of the local content, needed by POST
        response = await self.docker_registry_client_async.patch_blob_upload_from_disk(
            response["location"], file, **kwargs
        )
        return await self.docker_registry_client_async.put_blob_upload(
            response["location"], response["digest"], **kwargs
        )
        # TODO: Should we check self.layer_exists(image_name, digest) here, like docker CLI does?

    @ImageSource.check_dry_run
    async def put_manifest(
        self, manifest: Manifest, image_name: ImageName = None, **kwargs
    ) -> DockerRegistryClientAsyncPutManifest:
        return await self.docker_registry_client_async.put_manifest(
            image_name, manifest, **kwargs
        )

    async def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source: ImageSource,
        dest_image_name: ImageName,
        signature_type: SignatureTypes = SignatureTypes.SIGN,
        **kwargs,
    ) -> ImageSourceSignImage:
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
        LOGGER.debug("    Signature:\n%s", data["signature_value"])
        image_config = data["image_config"]
        config_digest = image_config.get_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest)

        # Generate a new registry manifest ...
        manifest = data["verify_image_data"]["manifest"].clone()
        manifest = cast(RegistryV2Manifest, manifest)
        manifest.set_config_digest(config_digest, len(image_config.get_bytes()))
        data = cast(ImageSourceSignImage, data)
        data["manifest_signed"] = manifest

        await dest_image_source.put_image(
            self,
            dest_image_name,
            manifest,
            image_config,
            data["verify_image_data"]["compressed_layer_files"],
            **kwargs,
        )

        dest_image_name.digest = manifest.get_digest()

        if not self.dry_run:
            LOGGER.debug("Created new image: %s", dest_image_name.resolve_name())

        return data

    async def verify_image_integrity(
        self, image_name: ImageName, **kwargs
    ) -> ImageSourceVerifyImageIntegrity:
        data = await self._verify_image_config(image_name, **kwargs)

        # Reconcile manifest layers and image layers (in order)...
        compressed_layer_files = []
        uncompressed_layer_files = []
        for i, layer in enumerate(data["manifest_layers"]):
            # Retrieve the registry image layer and verify the digest ...
            compressed_layer_files.append(await aiotempfile())
            data_compressed = await self.get_image_layer_to_disk(
                image_name, layer, compressed_layer_files[i], **kwargs
            )
            must_be_equal(
                layer,
                data_compressed["digest"],
                f"Registry layer[{i}] digest mismatch",
            )
            must_be_equal(
                os.path.getsize(compressed_layer_files[i].name),
                data_compressed["size"],
                f"Registry layer[{i}] size mismatch",
            )

            # Decompress (convert) the registry image layer into the image layer
            # and verify the digest ...
            uncompressed_layer_files.append(await aiotempfile())
            data_uncompressed = await gunzip(
                compressed_layer_files[i].name, uncompressed_layer_files[i]
            )
            must_be_equal(
                data["image_layers"][i],
                data_uncompressed["digest"],
                f"Image layer[{i}] digest mismatch",
            )

        LOGGER.debug("Integrity check passed.")

        return {
            "compressed_layer_files": compressed_layer_files,
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": uncompressed_layer_files,
        }
