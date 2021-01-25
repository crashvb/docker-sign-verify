#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifest lists."""

from typing import List

from docker_registry_client_async import (
    DockerMediaTypes,
    FormattedSHA256,
    Manifest,
    OCIMediaTypes,
)


class RegistryV2ManifestList(Manifest):
    """
    Class to retrieve and manipulate image manifest lists.
    """

    @staticmethod
    def from_manifest(manifest: Manifest) -> "RegistryV2ManifestList":
        """
        Creates an image manifest list from a given manifest.

        Args:
            manifest: The manifest from which to create the image manifest list.

        Returns:
            The corresponding image manifest list.
        """
        return RegistryV2ManifestList(
            manifest.get_bytes(), media_type=manifest.get_media_type()
        )

    def get_manifests(
        self, *, architecture: str = None, os: str = None
    ) -> List[FormattedSHA256]:
        """
        Retrieves the listing of manifest layer identifiers.

        Args:
            architecture: The name of the CPU architecture.
            os: The name of the operating system.

        Returns:
            list: Manifest identifiers in the form: <hash type>:<digest value>.
        """
        if self.get_media_type() not in [
            DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2,
            OCIMediaTypes.IMAGE_INDEX_V1,
        ]:
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
            if os and manifest.get("platform", "").get("os", "") != os:
                continue
            result.append(FormattedSHA256.parse(manifest["digest"]))
        return result
