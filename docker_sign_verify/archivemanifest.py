#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifests."""

from typing import List

from docker_registry_client_async import FormattedSHA256, ImageName

from .manifest import Manifest


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
            repotag = f"{image_name.image}:{image_name.tag}"
            for config in self.get_json():
                if config["RepoTags"] and repotag in config["RepoTags"]:
                    return config
        else:
            manifest_name = f"{image_name.resolve_digest().sha256}.json"
            return [
                config
                for config in self.get_json()
                if config["Config"] == manifest_name
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
        json = self.get_json()
        json.append(config)
        self._set_json(json)

    # Manifest Members

    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        config = self.get_config(image_name)
        return FormattedSHA256(config["Config"][:-5])

    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        layers = self.get_config(image_name)["Layers"]
        return [ArchiveManifest.layer_to_digest(l) for l in layers]
