#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifests."""

import abc
import copy
import json

from pathlib import Path
from typing import List

from .imageconfig import ImageConfig
from .imagename import ImageName
from .utils import formatted_digest, read_file, FormattedSHA256


class Manifest(abc.ABC):
    """
    Abstract class to retrieve and manipulate image source manifests.
    """

    def __init__(self, manifest: bytes):
        """
        Args:
            manifest: The raw image source manifest value.
        """
        self.json = json.loads(manifest)

    def __str__(self):
        return json.dumps(self.json)

    @abc.abstractmethod
    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        """
        Retrieves the image configuration digest value from the image source manifest.

        Args:
            image_name: The image name.

        Returns:
            The image configuration digest value in the form: <hash type>:<digest value>.
        """

    @abc.abstractmethod
    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        """
        Retrieves the listing of manifest layer identifiers.

        Args:
            image_name: The image name.

        Returns:
            list: Layer identifiers in the form: <hash type>:<digest value>.
        """

    # TODO: Move weird, type-specific, manifest logic to these methods
    # @abc.abstractmethod
    # def copyfrom(self, src_image_source: ImageSource, dest_image_name, config_digest_signed) -> str:


class ArchiveManifest(Manifest):
    """
    Image source manifest for docker archives.
    """

    @staticmethod
    def layer_to_digest(layer: str) -> FormattedSHA256:
        """
        Coverts a archive layer identifier to a digest value.

        Args:
            layer: The archive layer identifier (relative tar path).

        Returns:
            The corresponding digest value in the form: <hash type>:<digest value>.
        """
        return FormattedSHA256(layer[:-10])

    @staticmethod
    def digest_to_layer(digest: FormattedSHA256) -> str:
        """
        Converts a digest value to a archive layer identifier.

        Args:
            digest: The digest value in the form: <hash type>:<digest value>.

        Returns:
            The corresponding archive layer identifier (relative tar path).
        """
        return "{0}/layer.tar".format(digest.sha256)

    def get_config(self, image_name: ImageName):
        """
        Retrieves the image configuration dictionary for a given image name from the image source manifest.

        Args:
            image_name: The image name.

        Returns:
            A dictionary as defined by the Docker specification.
            dict:
                Config: Image configuration (relative tar path).
                RepoTags: Docker repository tags.
                Layers: List of image layer (relative tar paths).
        """
        if image_name.tag:
            repotag = str(image_name)
            for config in self.json:
                if config["RepoTags"] and repotag in config["RepoTags"]:
                    return config
        else:
            return [
                config
                for config in self.json
                if config["Config"] == "{0}.json".format(image_name.image)
            ][0]
        raise RuntimeError("Unable to locate configuration in archive manifest!")

    def append_config(
        self,
        config_digest: FormattedSHA256,
        layers: List[FormattedSHA256],
        repotags: List = None,
    ):
        """
        Appends an image configuration dictionary to the image source manifest

        Args:
            config_digest: Image configuration digest in the form <hash type>:<digest value>.
            layers: List of image layer identifiers in the form: <hash type>:<digest_value>.
            repotags: List of docker repository tags.
        """
        config = {
            "Config": "{0}.json".format(config_digest.sha256),
            "Layers": [ArchiveManifest.digest_to_layer(l) for l in layers],
        }
        if repotags:
            config["RepoTags"] = repotags

        # TODO: Check to make sure it doesn't already exist?
        self.json.append(config)

    # Manifest Members

    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        config = self.get_config(image_name)
        return FormattedSHA256(config["Config"][:-5])

    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        layers = self.get_config(image_name)["Layers"]
        return [ArchiveManifest.layer_to_digest(l) for l in layers]


class RegistryV2Manifest(Manifest):
    """
    Manifest list, aka "fat manifest" as defined in:

    https://github.com/docker/distribution/blob/master/docs/spec/manifest-v2-2.md
    """

    def set_config_digest(self, config_digest: FormattedSHA256, size: int):
        """
        Assigns the image configuration digest and size in the image source manifest.

        Args:
            config_digest: Image configuration digest in the form <hash type>:<digest value>.
            size: Image configuration size in bytes.
        """
        if self.json["schemaVersion"] == 2:
            self.json["config"]["digest"] = config_digest
            self.json["config"]["size"] = size
        else:
            raise RuntimeError(
                "Unsupported schema version: {0}".format(self.json["schemaVersion"])
            )

    def set_layers(self, layers: List[FormattedSHA256]):
        """
        Assigns the list of manifest layer identifiers.

        Note: It is not the intention of this utility to modify layer content! As such we only support updating the
              manifest layer identifiers as part of layer replication between two disjoint registries. (i.e.
              Modification of the overall layer count, order, or individual layer sizes is explicitly not implemented.)

        Args:
            layers: List of manifest layer identifiers in the form: <hash type>:<digest_value>.
        """
        if self.json["schemaVersion"] == 2:
            for i, layer in enumerate(self.json["layers"]):
                layer["digest"] = layers[i]
        else:
            raise RuntimeError(
                "Unsupported schema version: {0}".format(self.json["schemaVersion"])
            )

    # Manifest Members

    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        if self.json["schemaVersion"] == 2:
            result = FormattedSHA256.parse(self.json["config"]["digest"])
        else:
            raise RuntimeError(
                "Unsupported schema version: {0}".format(self.json["schemaVersion"])
            )

        return result

    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        if self.json["schemaVersion"] == 2:
            result = [FormattedSHA256.parse(l["digest"]) for l in self.json["layers"]]
        else:
            raise RuntimeError(
                "Unsupported schema version: {0}".format(self.json["schemaVersion"])
            )

        return result


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
        key_name = copy.deepcopy(image_name)
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
            result = formatted_digest("{0} {1}".format(parent, layer).encode("utf-8"))
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
        key = DeviceMapperRepositoryManifest._get_repository_key(image_name)
        image = self.json["Repositories"].get(key, {})
        image[str(image_name)] = config_digest
        self.json["Repositories"][key] = image

    # Manifest Members

    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        key = DeviceMapperRepositoryManifest._get_repository_key(image_name)
        image = self.json["Repositories"].get(key, {})
        return FormattedSHA256.parse(image.get(str(image_name), None))

    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        # TODO: How can this be reimplemented to avoid duplicate code?
        DM_CONTENT_ROOT = Path(
            "/var/lib/docker/image/devicemapper/imagedb/content/sha256"
        )
        path = DM_CONTENT_ROOT.joinpath(self.get_config_digest(image_name).sha256)
        image_config = ImageConfig(read_file(path))

        result = []
        parent = None
        for layer in image_config.get_image_layers():
            result.append(
                DeviceMapperRepositoryManifest.get_combined_layerid(parent, layer)
            )
            parent = result[-1]

        return result
