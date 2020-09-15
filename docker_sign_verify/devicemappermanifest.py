#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifests."""

from pathlib import Path
from typing import List

from docker_registry_client_async import FormattedSHA256, ImageName

from .imageconfig import ImageConfig
from .manifest import Manifest
from .utils import read_file


class DeviceMapperRepositoryManifest(Manifest):
    """
    Image source manifest for docker repositories.
    """

    @staticmethod
    def _get_repository_key(image_name: ImageName) -> str:
        """
        Retrieves the repository key for a given image name.

        Args:
            image_name: Image name for which to retrieve the key.

        Returns:
            The corresponding repository key.
        """
        key_name = image_name.clone()
        key_name.tag = None
        return str(key_name)

    @staticmethod
    def get_combined_layerid(
        parent: FormattedSHA256, layer: FormattedSHA256
    ) -> FormattedSHA256:
        """
        Retrieves the layer identifier for a given parent-layer combination.

        Args:
            parent: The parent layer identifier.
            layer:  The layer identifier.

        Returns:
            The corresponding layer identifier.
        """
        result = layer
        if parent:
            # Note: The image layer is the digest value of the formatted string.
            result = FormattedSHA256.calculate(f"{parent} {layer}".encode("utf-8"))
        return result

    def override_config(self, config_digest: FormattedSHA256, image_name: ImageName):
        """
        Assigns the image configuration digest for a given image name in the image source manifest.

        Args:
            config_digest: Image configuration digest in the form <hash type>:<digest value>.
            image_name: The image name.
        """

        # Note: registry.json can only contain two formats:
        #       [<endpoint>/]<image>:<tag>
        #       [<endpoint>/]<image>@<hash type>:<digest value>
        json = self.get_json()
        key = DeviceMapperRepositoryManifest._get_repository_key(image_name)
        image = json["Repositories"].get(key, {})
        image[str(image_name)] = config_digest
        json["Repositories"][key] = image
        self._set_json(json)

    # Manifest Members

    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        key = DeviceMapperRepositoryManifest._get_repository_key(image_name)
        image = self.get_json()["Repositories"].get(key, {})
        return FormattedSHA256.parse(image.get(str(image_name), None))

    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        # TODO: How can this be reimplemented to avoid duplicate code?
        DM_CONTENT_ROOT = Path(
            "/var/lib/docker/image/devicemapper/imagedb/content/sha256"
        )
        path = DM_CONTENT_ROOT.joinpath(self.get_config_digest(image_name).sha256)
        # TODO: Convert to async
        with path.open("r+b") as file:
            image_config = ImageConfig(file.read())

        result = []
        parent = None
        for layer in image_config.get_image_layers():
            result.append(
                DeviceMapperRepositoryManifest.get_combined_layerid(parent, layer)
            )
            parent = result[-1]

        return result
