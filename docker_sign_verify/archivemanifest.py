#!/usr/bin/env python

"""Classes that provide abstractions of different image source manifests."""

import json
import re

from typing import List, Set, Union

from docker_registry_client_async import FormattedSHA256, ImageName, JsonBytes

from .manifest import Manifest


class ArchiveChangeset(JsonBytes):
    """
    Image Filesystem Changeset as defined in:

    https://github.com/moby/moby/blob/master/image/spec/v1.md
    """

    @staticmethod
    def get_repository_tag(image_name: ImageName):
        """
        Constructs a repository tag from an image name.

        Args:
            image_name: Image name from which to construct the repository tag.

        Returns:
            The normalized repository tag.
        """
        return ArchiveChangeset.normalize_tags(
            [f"{image_name.image}:{image_name.tag}"]
        )[0]

    @staticmethod
    def normalize_tags(tags: Union[List[str], Set[str]]) -> List[str]:
        """
        Normalizes a list of tags to conform with the output of docker-save.
        Args:
            tags: The list of tags to be normalized.

        Returns:
            The normalized list.
        """
        # TODO: 'library/' image prefix does not appear to be exported by docker-save ...
        if not tags:
            return tags
        return [re.sub(r"^library/", "", tag) for tag in tags]

    def append_manifest(self, manifest: "ArchiveManifest"):

        """
        Appends an archive manifest to the archive changeset.

        Args:
            manifest: The archive manifest to be appended.
        """
        # Remove the image if it already exists
        self.remove_manifest(FormattedSHA256(manifest.get_json()["Config"][:-5]))

        # Remove all tags being assigned to the new image ...
        tags = ArchiveChangeset.normalize_tags(manifest.get_tags())
        if tags:
            self.remove_tags(tags)

        # Append the new image configuration ...
        _json = self.get_json()
        _json.append(manifest.get_json())
        self._set_json(_json)

    def get_manifest(self, image_name: ImageName) -> "ArchiveManifest":
        """
        Retrieves the archive manifest for a given image name from the archive changeset.

        Args:
            image_name: The image name.

        Returns:
            The corresponding archive manifest.
        """
        if image_name.digest:
            for manifest in self.get_manifests():
                if manifest.get_config_digest() == image_name.resolve_digest():
                    return manifest
        else:
            tag = ArchiveChangeset.get_repository_tag(image_name)
            for manifest in self.get_manifests():
                tags = manifest.get_tags()
                if tags and tag in manifest.get_tags():
                    return manifest
        raise RuntimeError(
            f"Unable to locate configuration in archive manifest for: {image_name.resolve_name()}"
        )

    def get_manifests(self):
        """
        Retrieves the list of archive manifests contained within the archive changeset.

        Returns:
            The list of archive manifests contained within the archive changset.
        """
        return [
            ArchiveManifest(json.dumps(manifest).encode("utf-8"))
            for manifest in self.get_json()
        ]

    def remove_manifest(self, config_digest: FormattedSHA256):
        """
        Removes an archive manifest from the archive changeset.

        Args:
            config_digest: Image configuration digest in the form <hash type>:<digest value>.
        """
        manifests = [
            manifest.get_json()
            for manifest in self.get_manifests()
            if manifest.get_config_digest() != config_digest
        ]
        self._set_json(manifests)

    def remove_tags(self, tags: Union[List[str], Set[str]]):
        """
        Removes a list of repository tags from all archive manifests within the archive changeset.

        Args:
            tags: A list of tags to be removed from all image configurations.
        """
        manifests = self.get_manifests()
        for manifest in manifests:
            manifest.remove_tags(tags)
        manifests = [manifest.get_json() for manifest in manifests]
        self._set_json(manifests)


class ArchiveManifest(Manifest):
    """
    Image source manifest for docker archives.
    """

    @staticmethod
    def digest_to_layer(digest: FormattedSHA256) -> str:
        """
        Converts a digest value to a archive layer identifier.

        Args:
            digest: The digest value in the form: <hash type>:<digest value>.

        Returns:
            The corresponding archive layer identifier (relative tar path).
        """
        return f"{digest.sha256}/layer.tar"

    @staticmethod
    def from_json(_json) -> "ArchiveManifest":
        """
        Initializes an archive manifest from a JSON object.

        Args:
            _json: JSON object with which to initialize the archive manifest.

        Returns:
            The newly initialized archive manifest.
        """
        archive_manifest = ArchiveManifest(b"{}")
        archive_manifest._set_json(_json)  # pylint: disable=protected-access
        return archive_manifest

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

    def get_tags(self) -> Set[str]:
        """
        Retrieves the set of repository tags.

        Returns:
            The set of repository tags.
        """
        result = self.get_json()["RepoTags"]
        return set(result) if result else result

    def remove_tags(self, tags: Union[List[str], Set[str]]):
        """
        Removes a list of repository tags.

        Args:
            tags: A list of tags to be removed from all image configurations.
        """
        existing = self.get_tags()
        if not existing:
            existing = set()
        delta = set(tags) if tags else set()
        self.set_tags(existing - delta)

    def set_config_digest(self, config_digest: FormattedSHA256):
        """
        Assigns the image configuration digest.

        Args:
            config_digest: Image configuration digest in the form <hash type>:<digest value>.
        """
        _json = self.get_json()
        _json["Config"] = f"{config_digest.sha256}.json"
        self._set_json(_json)

    def set_layers(self, layers: List[FormattedSHA256]):
        """
        Assigns the list of manifest layer identifiers.

        Args:
            layers: List of manifest layer identifiers in the form: <hash type>:<digest_value>.
        """
        _json = self.get_json()
        _json["Layers"] = [ArchiveManifest.digest_to_layer(digest) for digest in layers]
        self._set_json(_json)

    def set_tags(self, tags: Union[List[str], Set[str], None]):
        """
        Assigns the list of repository tags.

        Args:
            tags: The list of repository tags to be assigned.
        """
        _json = self.get_json()
        _json["RepoTags"] = list(tags) if tags else None
        self._set_json(_json)

    # Manifest Members

    def get_config_digest(self, image_name: ImageName = None) -> FormattedSHA256:
        return FormattedSHA256(self.get_json()["Config"][:-5])

    def get_layers(self, image_name: ImageName = None) -> List[FormattedSHA256]:
        layers = self.get_json()["Layers"]
        return [ArchiveManifest.layer_to_digest(layer) for layer in layers]


class ArchiveRepositories(JsonBytes):
    """
    Archive repositories as defined in:

    https://github.com/moby/moby/blob/master/image/spec/v1.md
    """

    def get_tag(self, image_name: ImageName):
        """
        Retrieves a repository tag for a given image.

        Args:
            image_name: The image for which to assign the tag

        Returns:
            The repository tag, or None.
        """
        image = ArchiveChangeset.normalize_tags([image_name.image])[0]
        return self.get_json().get(image, {}).get(image_name.resolve_tag(), None)

    def set_tag(self, image_name: ImageName, digests: FormattedSHA256):
        """
        Assigns a repository tag.

        Args:
            image_name: The image for which to assign the tag
            digests: The value to be assigned to the tag
        """
        _json = self.get_json()
        image = ArchiveChangeset.normalize_tags([image_name.image])[0]
        if not image in _json:
            _json[image] = {}
        _json[image][image_name.resolve_tag()] = digests.sha256
        self._set_json(_json)
