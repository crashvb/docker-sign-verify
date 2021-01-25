#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifests."""

import abc

from typing import List

from docker_registry_client_async import (
    FormattedSHA256,
    ImageName,
    Manifest as DRCAManifest,
)


class Manifest(abc.ABC, DRCAManifest):
    """
    Abstract class to retrieve and manipulate image manifests.
    """

    def __init__(self, manifest: bytes, *, media_type: str = None, **kwargs):
        # pylint: disable=useless-super-delegation
        """
        Args:
            manifest: The raw image manifest value.
            media_type: The media type of the image manifest.
        """
        super().__init__(manifest, media_type=media_type, **kwargs)

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
        Retrieves the list of manifest layer identifiers.

        Args:
            image_name: The image name.

        Returns:
            list: Layer identifiers in the form: <hash type>:<digest value>.
        """

    # TODO: Move weird, type-specific, manifest logic to these methods
    # @abc.abstractmethod
    # def copyfrom(self, src_image_source: ImageSource, dest_image_name, config_digest_signed) -> str:
