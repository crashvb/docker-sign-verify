#!/usr/bin/env python

"""Classes that provide a source of docker images."""

import datetime
import io
import logging
import os
import random
import tempfile
from typing import Dict, List

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_registry_client_async.utils import must_be_equal

from .archivemanifest import ArchiveManifest
from .imageconfig import ImageConfig, SignatureTypes
from .imagesource import ImageSource
from .manifest import Manifest
from .signer import Signer
from .utils import (
    file_exists_in_tar,
    tar,
    tar_add_file,
    tar_delete_file,
    tar_mkdir,
    untar,
)

LOGGER = logging.getLogger(__name__)


class ArchiveImageSource(ImageSource):
    """
    Docker archive image source.
    """

    FILE_ARCHIVE_MANIFEST = "manifest.json"

    def __init__(self, *, archive, **kwargs):
        """
        Args:
            archive: Path to the docker image archive.
        """
        super().__init__(**kwargs)
        self.archive = archive

    def _file_exists(self, name) -> bool:
        """
        Checks if a give file exists within this image source.

        Args:
            name: Name of the file to be checked.

        Returns:
            bool: True if the file exists, False otherwise.
        """
        with open(self.archive, "rb") as file_in:
            return file_exists_in_tar(file_in, name)

    def get_file_from_archive(self, path):
        """
        Retrieves a file from within this image source.

        Args:
            path: Relative path of the file to be retrieved.

        Returns:
            The file content.
        """
        bytesio = io.BytesIO()
        with open(self.archive, "rb") as file:
            untar(file, path, bytesio)
        return bytesio.read()

    # ImageSource Members

    async def get_image_config(self, image_name: ImageName, **kwargs) -> ImageConfig:
        manifest = await self.get_manifest()
        config = manifest.get_config(image_name)
        return ImageConfig(self.get_file_from_archive(config["Config"]))

    async def get_image_layer_to_disk(
        self, image_name: ImageName, layer: FormattedSHA256, file, **kwargs
    ):
        # TODO: Convert to async
        with open(self.archive, "rb") as file_in:
            return untar(file_in, ArchiveManifest.digest_to_layer(layer), file)

    # TODO: def put_image_layer(self, image, content):

    async def get_manifest(self, image_name: ImageName = None, **kwargs) -> Manifest:
        # TODO: Convert to async
        raw_archive_manifest = self.get_file_from_archive(
            ArchiveImageSource.FILE_ARCHIVE_MANIFEST
        )
        return ArchiveManifest(raw_archive_manifest)

    async def layer_exists(
        self, image_name: ImageName, layer: FormattedSHA256, **kwargs
    ) -> bool:
        # TODO: Convert to async
        return self._file_exists(ArchiveManifest.digest_to_layer(layer))

    async def put_image(
        self,
        image_source,
        image_name: ImageName,
        manifest: Manifest,
        image_config: ImageConfig,
        layer_files: List,
        **kwargs,
    ):
        # TODO: Implement this method, refactor sign_image to use it ...
        raise NotImplementedError

    async def put_image_config(
        self, image_name: ImageName, image_config: ImageConfig, **kwargs
    ):
        # TODO: Convert to async
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_config")
            return
        digest = image_config.get_digest()
        name = "{0}.json".format(digest.sha256)
        if not self._file_exists(name):
            with open(self.archive, "rb+") as file_out:
                tar_add_file(file_out, name, image_config.get_bytes())

    async def put_image_layer(self, image_name: ImageName, content, **kwargs):
        raise NotImplementedError

    async def put_image_layer_from_disk(
        self, image_name: ImageName, file, **kwargs
    ) -> FormattedSHA256:
        # TODO: Convert to async
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer_from_disk")
            return FormattedSHA256("0" * 64)
        # TODO: Do we really want to use random garbage here???
        #       Look into moby/.../save.go to find what to use instead.
        digest = FormattedSHA256.calculate(
            "{0}{1}{2}".format(
                str(image_name), datetime.datetime.now(), random.randint(1, 101)
            ).encode("utf-8")
        )
        layer = ArchiveManifest.digest_to_layer(digest)
        with open(self.archive, "rb+") as file_out:
            tar_mkdir(file_out, os.path.dirname(layer))
            file_out.seek(0)
            tar(file_out, layer, file)
        return digest

    async def put_manifest(
        self, manifest: Manifest, image_name: ImageName = None, **kwargs
    ):
        # TODO: Convert to async
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_manifest")
            return
        with open(self.archive, "rb+") as file_out:
            tar_delete_file(file_out, ArchiveImageSource.FILE_ARCHIVE_MANIFEST)
            file_out.seek(0)
            tar_add_file(
                file_out,
                ArchiveImageSource.FILE_ARCHIVE_MANIFEST,
                str(manifest).encode("utf-8"),
            )

    async def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source: ImageSource,
        dest_image_name: ImageName,
        signature_type: SignatureTypes = SignatureTypes.SIGN,
        **kwargs,
    ):
        LOGGER.debug(
            "%s: %s ...",
            "Endorsing"
            if signature_type == SignatureTypes.ENDORSE
            else "Signing"
            if signature_type == SignatureTypes.SIGN
            else "Resigning",
            src_image_name.resolve_name(),
        )

        # Generate a signed image configuration ...
        data = await self._sign_image_config(signer, src_image_name, signature_type)
        manifest = data["verify_image_data"]["manifest"]
        LOGGER.debug("    Signature:\n%s", data["signature_value"])
        image_config = data["image_config"]

        # Replicate all of the image layers ...
        LOGGER.debug("    Replicating image layers ...")
        archive_layers = manifest.get_layers(src_image_name)
        archive_layers_changed = archive_layers.copy()
        for i, archive_layer in enumerate(archive_layers):
            if not dest_image_source.layer_exists(dest_image_name, archive_layer):
                # Update the layer
                digest = dest_image_source.put_image_layer_from_disk(
                    dest_image_name,
                    data["verify_image_data"]["uncompressed_layer_files"][i],
                )
                archive_layers_changed[i] = digest
        archive_layers = archive_layers_changed

        # Push the new image configuration ...
        config_digest_signed = image_config.get_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest_signed)
        await dest_image_source.put_image_config(dest_image_name, image_config)

        # Generate a new archive manifest, and push ...
        if isinstance(dest_image_source, ArchiveImageSource):
            manifest_signed = (
                await dest_image_source.get_manifest()
            )  # type: ArchiveManifest

            repotags = None
            if dest_image_name.tag:
                repotags = [str(dest_image_name)]
                manifest_signed.append_config(
                    config_digest_signed, archive_layers, repotags
                )
            data["manifest_signed"] = manifest_signed
            # TODO: make sure to remove conflicting tags in "other" config entries
            await dest_image_source.put_manifest(manifest_signed)
            # TODO: Update foo.tar:/repositories as well
        elif type(dest_image_source).__name__ == "RegistryV2ImageSource":
            raise NotImplementedError
        elif type(dest_image_source).__name__ == "DeviceMapperRepositoryImageSource":
            raise NotImplementedError
        else:
            raise RuntimeError(
                "Unknown derived class: {0}".format(type(dest_image_source))
            )

        if not self.dry_run:
            LOGGER.debug("Created new image: %s", dest_image_name.resolve_name())

        return data

    async def verify_image_integrity(self, image_name: ImageName, **kwargs) -> Dict:
        data = await self._verify_image_config(image_name)

        # Reconcile manifest layers and image layers (in order)...
        uncompressed_layer_files = []
        for i, layer in enumerate(data["manifest_layers"]):
            # Retrieve the archive image layer and verify the digest ...
            uncompressed_layer_files.append(tempfile.NamedTemporaryFile())
            data_uncompressed = await self.get_image_layer_to_disk(
                image_name, layer, uncompressed_layer_files[i]
            )
            must_be_equal(
                data["image_layers"][i],
                data_uncompressed["digest"],
                "Archive layer[{0}] digest mismatch".format(i),
            )

        LOGGER.debug("Integrity check passed.")

        return {
            "compressed_layer_files": "TODO",
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": uncompressed_layer_files,
        }
