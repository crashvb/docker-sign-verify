#!/usr/bin/env python

"""Classes that provide a source of docker images."""

import datetime
import io
import logging
import random
import tarfile

from typing import cast, List
from pathlib import Path

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_registry_client_async.utils import must_be_equal

from .aiotempfile import open as aiotempfile
from .archivemanifest import ArchiveChangeset, ArchiveManifest, ArchiveRepositories
from .imageconfig import ImageConfig, SignatureTypes
from .imagesource import (
    ImageSource,
    ImageSourceGetImageLayerToDisk,
    ImageSourceSignImage,
    ImageSourceVerifyImageIntegrity,
)
from .manifest import Manifest
from .signer import Signer
from .utils import (
    file_exists_in_tar,
    tar_add_file,
    tar_add_file_from_disk,
    tar_delete_file,
    tar_mkdir,
    untar,
)

LOGGER = logging.getLogger(__name__)


class ArchiveImageSource(ImageSource):
    """
    Docker archive image source.
    """

    FILE_ARCHIVE_CHANGESET_MANIFEST = "manifest.json"
    FILE_ARCHIVE_CHANGESET_REPOSITORIES = "repositories"

    def __init__(self, *, archive: Path, **kwargs):
        """
        Args:
            archive: Path to the docker image archive.
        """
        super().__init__(**kwargs)
        self.archive = archive

        if not self.archive.exists():
            LOGGER.debug("Initializing tar: %s", self.archive)
            with tarfile.open(self.archive, "x"):
                pass

    async def _file_exists(self, name) -> bool:
        """
        Checks if a give file exists within this image source.

        Args:
            name: Name of the file to be checked.

        Returns:
            bool: True if the file exists, False otherwise.
        """
        with open(self.archive, "rb") as file_in:
            return file_exists_in_tar(file_in, name)

    async def get_archive_changeset(self) -> ArchiveChangeset:
        """
        Retrieves the archive changeset from within this image source.

        Returns:
            The archive changeset from within this image source.
        """
        raw_archive_changeset = b"[]"
        if await self._file_exists(ArchiveImageSource.FILE_ARCHIVE_CHANGESET_MANIFEST):
            raw_archive_changeset = await self.get_file_from_archive(
                ArchiveImageSource.FILE_ARCHIVE_CHANGESET_MANIFEST
            )
        return ArchiveChangeset(raw_archive_changeset)

    async def get_archive_repositories(self) -> ArchiveRepositories:
        """
        Retrieves the archive repositories from within this image source.

        Returns:
            The archive repositories from within this image source.
        """
        raw_archive_repositories = b"{}"
        if await self._file_exists(
            ArchiveImageSource.FILE_ARCHIVE_CHANGESET_REPOSITORIES
        ):
            raw_archive_repositories = await self.get_file_from_archive(
                ArchiveImageSource.FILE_ARCHIVE_CHANGESET_REPOSITORIES
            )
        return ArchiveRepositories(raw_archive_repositories)

    async def get_file_from_archive(self, path):
        """
        Retrieves a file from within this image source.

        Args:
            path: Relative path of the file to be retrieved.

        Returns:
            The file content.
        """
        bytesio = io.BytesIO()
        with open(self.archive, "rb") as file:
            await untar(file, path, bytesio, file_out_is_async=False)
        return bytesio.read()

    async def put_archive_changeset(self, archive_changeset: ArchiveChangeset):
        """
        Assigns the archive changeset to this image source.

        Args:
            archive_changeset:  The archive changeset to be assigned.
        """
        with open(self.archive, "rb+") as file_out:
            tar_delete_file(
                file_out, ArchiveImageSource.FILE_ARCHIVE_CHANGESET_MANIFEST
            )
            file_out.seek(0)
            tar_add_file(
                file_out,
                ArchiveImageSource.FILE_ARCHIVE_CHANGESET_MANIFEST,
                archive_changeset.get_bytes(),
            )

    async def put_archive_repositories(self, archive_repositories: ArchiveRepositories):
        """
        Assigns the archive repositories to this image source.

        Args:
            archive_repositories:  The archive repositories to be assigned.
        """
        with open(self.archive, "rb+") as file_out:
            tar_delete_file(
                file_out, ArchiveImageSource.FILE_ARCHIVE_CHANGESET_REPOSITORIES
            )
            file_out.seek(0)
            tar_add_file(
                file_out,
                ArchiveImageSource.FILE_ARCHIVE_CHANGESET_REPOSITORIES,
                archive_repositories.get_bytes(),
            )

    # TODO async def get_layer_metadata(digest: FormattedSHA256) -> TypingGetLayerMetadata:
    # TODO async def put_layer_metadata(json: str, version: str = "1.0"):

    # ImageSource Members

    async def get_image_config(self, image_name: ImageName, **kwargs) -> ImageConfig:
        manifest = await self.get_manifest(image_name)
        return ImageConfig(
            await self.get_file_from_archive(manifest.get_json()["Config"])
        )

    async def get_image_layer_to_disk(
        self, image_name: ImageName, layer: FormattedSHA256, file, **kwargs
    ) -> ImageSourceGetImageLayerToDisk:
        with open(self.archive, "rb") as file_in:
            return await untar(
                file_in, ArchiveManifest.digest_to_layer(layer), file, **kwargs
            )

    async def get_manifest(
        self, image_name: ImageName = None, **kwargs
    ) -> ArchiveManifest:
        archive_changeset = await self.get_archive_changeset()
        return archive_changeset.get_manifest(image_name)

    async def layer_exists(
        self, image_name: ImageName, layer: FormattedSHA256, **kwargs
    ) -> bool:
        return await self._file_exists(ArchiveManifest.digest_to_layer(layer))

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
        manifest_layers_changed = manifest_layers.copy()
        for i, manifest_layer in enumerate(manifest_layers):
            if not await self.layer_exists(image_name, manifest_layer, **kwargs):
                if isinstance(image_source, ArchiveImageSource):
                    digest = await self.put_image_layer_from_disk(
                        image_name, layer_files[i], **kwargs
                    )
                    manifest_layers_changed[i] = digest
                else:
                    raise NotImplementedError(
                        f"Translation from '{type(image_source)}' to '{type(self)}' is not supported!"
                    )

        # Register the new image layers in the manifest, and ensure that the tags exist ...
        manifest = cast(ArchiveManifest, manifest)
        manifest.set_layers(manifest_layers_changed)
        manifest.set_tags(
            [ArchiveChangeset.get_repository_tag(image_name)]
            if image_name.tag
            else None
        )

        # Register the new configuration in the repository tags ...
        if image_name.tag:
            archive_repositories = await self.get_archive_repositories()
            # TODO: Should we pull the first layer [0] or the last one [-1]?
            archive_repositories.set_tag(image_name, manifest.get_layers()[0])
            await self.put_archive_repositories(archive_repositories)

        # Replicate the image configuration ...
        LOGGER.debug("    Replicating image configuration ...")
        await self.put_image_config(image_name, image_config, **kwargs)

        # Replicate the manifest ...
        LOGGER.debug("    Replicating image manifest ...")
        if isinstance(image_source, ArchiveImageSource):
            await self.put_manifest(manifest, image_name, **kwargs)
        else:
            raise NotImplementedError(
                f"Translation from '{type(image_source)}' to '{type(self)}' is not supported!"
            )

    @ImageSource.check_dry_run
    async def put_image_config(
        self, image_name: ImageName, image_config: ImageConfig, **kwargs
    ):
        image_name = image_name.clone()
        if image_name.resolve_digest():
            image_name.digest = None
            LOGGER.debug(
                "It is not possible to store an image configuration to a non-deterministic digest!"
                " Adjusted destination: %s",
                image_name.resolve_name(),
            )

        image_config_digest = image_config.get_digest()
        name = f"{image_config_digest.sha256}.json"
        if not await self._file_exists(name):
            with open(self.archive, "rb+") as file_out:
                tar_add_file(file_out, name, image_config.get_bytes())

    @ImageSource.check_dry_run
    async def put_image_layer(
        self, image_name: ImageName, content, **kwargs
    ) -> FormattedSHA256:
        # TODO: Do we really want to use random garbage here???
        #       Look into moby/.../save.go to find what to use instead.
        digest = FormattedSHA256.calculate(
            "{0}{1}{2}".format(
                str(image_name), datetime.datetime.now(), random.randint(1, 101)
            ).encode("utf-8")
        )
        layer = ArchiveManifest.digest_to_layer(digest)
        with open(self.archive, "rb+") as file_out:
            tar_add_file(file_out, layer, content)
        return digest

    @ImageSource.check_dry_run
    async def put_image_layer_from_disk(
        self, image_name: ImageName, file, **kwargs
    ) -> FormattedSHA256:
        # pylint: disable=protected-access
        file_is_async = kwargs.get("file_is_async", True)
        if file_is_async:
            file = (
                file._file
            )  # DUCK PUNCH: Unwrap the file handle from the asynchronous object

        # TODO: Do we really want to use random garbage here???
        #       Look into moby/.../save.go to find what to use instead.
        digest = FormattedSHA256.calculate(
            "{0}{1}{2}".format(
                str(image_name), datetime.datetime.now(), random.randint(1, 101)
            ).encode("utf-8")
        )
        layer = ArchiveManifest.digest_to_layer(digest)
        with open(self.archive, "rb+") as file_out:
            tar_mkdir(file_out, str(Path(layer).parent))
            file_out.seek(0)
            tar_add_file_from_disk(file_out, layer, file)
        return digest

    @ImageSource.check_dry_run
    async def put_manifest(
        self, manifest: Manifest, image_name: ImageName = None, **kwargs
    ):
        archive_changeset = await self.get_archive_changeset()
        manifest = cast(ArchiveManifest, manifest)
        archive_changeset.append_manifest(manifest)
        await self.put_archive_changeset(archive_changeset)

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

        # Generate a new archive manifest ...
        manifest = data["verify_image_data"]["manifest"].clone()
        manifest = cast(ArchiveManifest, manifest)
        manifest.set_config_digest(config_digest)
        data = cast(ImageSourceSignImage, data)
        data["manifest_signed"] = manifest

        await dest_image_source.put_image(
            self,
            dest_image_name,
            manifest,
            image_config,
            data["verify_image_data"]["uncompressed_layer_files"],
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
        uncompressed_layer_files = []
        for i, layer in enumerate(data["manifest_layers"]):
            # Retrieve the archive image layer and verify the digest ...
            uncompressed_layer_files.append(await aiotempfile())
            data_uncompressed = await self.get_image_layer_to_disk(
                image_name, layer, uncompressed_layer_files[i]
            )
            must_be_equal(
                data["image_layers"][i],
                data_uncompressed["digest"],
                f"Archive layer[{i}] digest mismatch",
            )

        LOGGER.debug("Integrity check passed.")

        return {
            "compressed_layer_files": [],  # TODO: Implement this
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": uncompressed_layer_files,
        }
