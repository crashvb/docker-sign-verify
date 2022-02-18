#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifest lists."""

from typing import List

from docker_registry_client_async import (
    DockerMediaTypes,
    FormattedSHA256,
    Manifest,
    OCIMediaTypes,
)

TYPES = [DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2, OCIMediaTypes.IMAGE_INDEX_V1]


class RegistryV2ManifestList(Manifest):
    """
    Class to retrieve and manipulate image manifest lists.
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

    def __init__(self, *, manifest: Manifest):
        """
        Args:
            manifest: The raw image manifest value.
        """
        super().__init__(
            manifest=manifest.get_bytes(), media_type=manifest.get_media_type()
        )

    def get_manifests(
        self, *, architecture: str = None, operating_system: str = None
    ) -> List[FormattedSHA256]:
        """
        Retrieves the listing of manifest layer identifiers.

        Args:
            architecture: The name of the CPU architecture.
            operating_system: The name of the operating system.

        Returns:
            list: Manifest identifiers in the form: <hash type>:<digest value>.
        """
        if self.get_media_type() not in TYPES:
            raise NotImplementedError(
                f"Unsupported media type: {self.get_media_type()}"
            )

        result = []
        for manifest in self.get_json()["manifests"]:
            if (
                architecture
                and manifest.get("platform", "").get("architecture", "") != architecture
            ):
                continue
            if (
                operating_system
                and manifest.get("platform", "").get("os", "") != operating_system
            ):
                continue
            result.append(FormattedSHA256.parse(manifest["digest"]))
        return result
