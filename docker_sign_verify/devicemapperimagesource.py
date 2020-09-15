#!/usr/bin/env python

"""Classes that provide a source of docker images."""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_registry_client_async.utils import must_be_equal

from .devicemappermanifest import DeviceMapperRepositoryManifest
from .imageconfig import ImageConfig, SignatureTypes
from .imagesource import ImageSource
from .manifest import Manifest
from .signer import Signer
from .utils import (
    chunk_file,
    read_file,
    write_file,
)

LOGGER = logging.getLogger(__name__)


class DeviceMapperRepositoryImageSource(ImageSource):
    """
    Docker repository image source.
    """

    DOCKER_ROOT = Path("/var/lib/docker")
    DM_CONTENT_ROOT = DOCKER_ROOT.joinpath("image/devicemapper/imagedb/content/sha256")
    DM_LAYER_ROOT = DOCKER_ROOT.joinpath("image/devicemapper/layerdb/sha256")
    DM_METADATA_ROOT = DOCKER_ROOT.joinpath("devicemapper/metadata")
    DM_REPOSITORIES = DOCKER_ROOT.joinpath("image/devicemapper/repositories.json")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    # ImageSource Members

    async def get_image_config(self, image_name: ImageName, **kwargs) -> ImageConfig:
        manifest = await self.get_manifest()
        config_digest = manifest.get_config_digest(image_name)
        path = DeviceMapperRepositoryImageSource.DM_CONTENT_ROOT.joinpath(
            config_digest.sha256
        )
        return ImageConfig(await read_file(path))

    async def get_image_layer_to_disk(
        self, image_name: ImageName, layer: FormattedSHA256, file, **kwargs
    ):
        # TODO: Convert to async
        # Retrieve the devicemapper metadata ...
        path = DeviceMapperRepositoryImageSource.DM_LAYER_ROOT.joinpath(
            layer[7:], "cache-id"
        )
        _bytes = await read_file(path)
        cache_id = _bytes.decode("utf-8")
        if not cache_id:
            raise RuntimeError(f"Unable to find cache id for layer: {layer}")
        path = DeviceMapperRepositoryImageSource.DM_METADATA_ROOT.joinpath(cache_id)
        raw_metadata = read_file(path)
        metadata = json.loads(raw_metadata)
        if not (metadata["device_id"] or metadata["size"]):
            raise RuntimeError(
                f"Unable to find device id and / or size for layer: {layer}"
            )

        # Create the devicemapper table ...
        device_name = f"dsv-{layer}"
        # TODO: How to we find the vgname?
        volume_group = "/dev/mapper/rhel-docker--pool"
        table = "0 {0} thin {1} {2}".format(
            metadata["size"], volume_group, metadata["device_id"]
        )
        subprocess.run(
            ["/sbin/dmsetup", "create", device_name, "--table", table], check=True
        )

        # Mount the layer ...
        mount = Path(tempfile.mkdtemp())
        subprocess.run(
            [
                "mount",
                "-o",
                "ro",
                Path("/dev/mapper").joinpath(device_name),
                mount.absolute(),
            ],
            check=True,
        )

        # Reconstruct the layer tar ...
        path = DeviceMapperRepositoryImageSource.DM_LAYER_ROOT.joinpath(
            layer[7:], "tar-split.json.gz"
        )
        rootfs = mount.joinpath("rootfs")
        if not rootfs.exists():
            raise RuntimeError(f"Root filesystem does not exist for layer: {layer}")
        # TODO: Replace this with a pure-python implementation
        process = subprocess.Popen(
            ["tar-split", "asm", "--input", str(path), "--path", rootfs],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        # TODO: This still buffers the entire file in memory ...
        result = await chunk_file(process.stdout, file, file_in_is_async=False)
        return_code = process.wait(120)
        if return_code != 0:
            raise RuntimeError("Tar-split failed!")

        # Unmount the layer, remove the devicemapper table, delete the mountpoint ...
        subprocess.run(["umount", mount.absolute()], check=True)
        subprocess.run(["/sbin/dmsetup", "remove", device_name], check=True)
        mount.rmdir()

        return result

    async def get_manifest(self, image_name: ImageName = None, **kwargs) -> Manifest:
        _bytes = await read_file(DeviceMapperRepositoryImageSource.DM_REPOSITORIES)
        return DeviceMapperRepositoryManifest(_bytes)

    async def layer_exists(
        self, image_name: ImageName, layer: FormattedSHA256, **kwargs
    ) -> bool:
        # TODO: Convert to async
        result = False
        path_layer = DeviceMapperRepositoryImageSource.DM_LAYER_ROOT.joinpath(
            layer.sha256
        ).joinpath("cache-id")
        if path_layer.exists():
            _bytes = await read_file(path_layer)
            cache_id = _bytes.decode("utf-8")
            path_cache = DeviceMapperRepositoryImageSource.DM_METADATA_ROOT.joinpath(
                cache_id
            )
            result = path_cache.exists()
        return result

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
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_config")
            return
        # TODO: Remove debug code
        # TODO: Convert to async
        # path = DeviceMapperRepositoryImageSource.DM_CONTENT_ROOT.joinpath(image_config.get_digest().sha256)
        path = Path(
            "/tmp/docker-ridavis/image/devicemapper/imagedb/conent/sha256/"
        ).joinpath(image_config.get_digest().sha256)
        path.parent.mkdir(exist_ok=True, parents=True)
        await write_file(path, image_config.get_bytes())

    async def put_image_layer(self, image_name: ImageName, content, **kwargs):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer")
            return
        # TODO: Implement this method ...
        raise NotImplementedError

    async def put_image_layer_from_disk(self, image_name: ImageName, file, **kwargs):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer_from_disk")
            return
        # TODO: Implement this method ...
        raise NotImplementedError

    async def put_manifest(
        self, manifest: Manifest, image_name: ImageName = None, **kwargs
    ):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_manifest")
            return
        # TODO: Remove debug code
        # TODO: Convert to async
        # path = DeviceMapperRepositoryImageSource.DM_REPOSITORIES
        path = Path("/tmp/docker-ridavis/repositories.json")
        path.parent.mkdir(exist_ok=True, parents=True)
        await write_file(path, str(manifest).encode("utf-8"))

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
        repository_layers = manifest.get_layers(src_image_name)
        for i, repository_layer in enumerate(repository_layers):
            if not dest_image_source.layer_exists(dest_image_name, repository_layer):
                await dest_image_source.put_image_layer_from_disk(
                    dest_image_name,
                    data["verify_image_data"]["compressed_layer_files"][i],
                )
        # TODO: We we need to track the layer translations here? Is this possible for DM repos?

        # Push the new image configuration ...
        config_digest_signed = image_config.get_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest_signed)
        await dest_image_source.put_image_config(dest_image_name, image_config)

        # Generate a new repository manifest, and push ...
        if type(dest_image_source).__name__ == "ArchiveImageSource":
            raise NotImplementedError
        elif type(dest_image_source).__name__ == "RegistryV2ImageSource":
            raise NotImplementedError
        elif isinstance(dest_image_source, DeviceMapperRepositoryImageSource):
            manifest_signed = (
                await dest_image_source.get_manifest()
            )  # type: DeviceMapperRepositoryManifest

            if dest_image_name.tag:
                manifest_signed.override_config(config_digest_signed, dest_image_name)
            data["manifest_signed"] = manifest_signed
            await dest_image_source.put_manifest(manifest_signed, dest_image_name)
        else:
            raise RuntimeError(f"Unknown derived class: {type(dest_image_source)}")

        if not self.dry_run:
            LOGGER.debug("Created new image: %s", dest_image_name.resolve_name())

        return data

    async def verify_image_integrity(self, image_name: ImageName, **kwargs) -> Dict:
        data = await self._verify_image_config(image_name)

        # Note: We do not need to reconcile manifest layer ids here, as "we" derived them in
        # :func:docker_sign_verify.manifests.DeviceMapperRepositoryManifest.get_layers.

        # Reconcile manifest layers and image layers (in order)...
        uncompressed_layer_files = []
        for i, layer in enumerate(data["manifest_layers"]):
            # Retrieve the repository image layer and verify the digest ...
            uncompressed_layer_files.append(tempfile.NamedTemporaryFile())
            data_compressed = await self.get_image_layer_to_disk(
                image_name, layer, uncompressed_layer_files[i]
            )
            must_be_equal(
                data["image_layers"][i],
                data_compressed["digest"],
                f"Repository layer[{i}] digest mismatch",
            )

        LOGGER.debug("Integrity check passed.")

        return {
            "compressed_layer_files": "TODO",
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": uncompressed_layer_files,
        }
