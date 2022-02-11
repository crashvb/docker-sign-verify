#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifests."""

from typing import List

from docker_registry_client_async import (
    DockerMediaTypes,
    FormattedSHA256,
    ImageName,
    Manifest,
    OCIMediaTypes,
)

TYPES = [DockerMediaTypes.DISTRIBUTION_MANIFEST_V2, OCIMediaTypes.IMAGE_MANIFEST_V1]


class RegistryV2Manifest(Manifest):
    """
    Manifest list, aka "fat manifest" as defined in:

    https://github.com/docker/distribution/blob/master/docs/spec/manifest-v2-2.md
    """

    @staticmethod
    def is_type(manifest: Manifest) -> bool:
        """
        Checks if the media type of a given manifest is acceptable for this class.

        Args:
            manifest: The manifest to be checked.

        Returns:
            True if the manifest is acceptable, false otherwise.
        """
        return manifest.get_media_type() in TYPES

    @staticmethod
    def new_from(manifest: Manifest) -> "RegistryV2Manifest":
        """
        Creates an image manifest from a given manifest.

        Args:
            manifest: The manifest from which to create the manifest.

        Returns:
            The corresponding image manifest list.
        """
        # TODO: Follow up, and hopefully remove this method in favor of inlining ...
        # https://stackoverflow.com/questions/3464061/cast-base-class-to-derived-class-python-or-more-pythonic-way-of-extending-class
        # https://bugs.python.org/issue35048
        # manifest.__class__ = RegistryV2Manifest
        # return manifest

        # https://stackoverflow.com/questions/43057218/python-multiple-inheritance-copy-constructor-class-initialization-and-over
        return RegistryV2Manifest(
            manifest=manifest.bytes, media_type=manifest.media_type
        )

    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        if self.get_media_type() not in TYPES:
            raise NotImplementedError(
                f"Unsupported media type: {self.get_media_type()}"
            )

        return FormattedSHA256.parse(self.get_json()["config"]["digest"])

    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        if self.get_media_type() not in TYPES:
            raise NotImplementedError(
                f"Unsupported media type: {self.get_media_type()}"
            )

        return [
            FormattedSHA256.parse(layer["digest"])
            for layer in self.get_json()["layers"]
        ]

    def set_config_digest(self, config_digest: FormattedSHA256, size: int):
        """
        Assigns the image configuration digest and size in the image source manifest.

        Args:
            config_digest: Image configuration digest in the form <hash type>:<digest value>.
            size: Image configuration size in bytes.
        """
        if self.get_media_type() not in TYPES:
            raise NotImplementedError(
                f"Unsupported media type: {self.get_media_type()}"
            )

        json = self.get_json()
        json["config"]["digest"] = config_digest
        json["config"]["size"] = size
        self._set_json(json)

    def set_layers(self, layers: List[FormattedSHA256]):
        """
        Assigns the list of manifest layer identifiers.

        Note: It is not the intention of this utility to modify layer content! As such we only support updating the
              manifest layer identifiers as part of layer replication between two disjoint registries. (i.e.
              Modification of the overall layer count, order, or individual layer sizes is explicitly not implemented.)

        Args:
            layers: List of manifest layer identifiers in the form: <hash type>:<digest_value>.
        """
        if self.get_media_type() not in TYPES:
            raise NotImplementedError(
                f"Unsupported media type: {self.get_media_type()}"
            )

        json = self.get_json()
        for i, layer in enumerate(json["layers"]):
            layer["digest"] = layers[i]
        self._set_json(json)
