#!/usr/bin/env python

"""Class that provides parsing and formatting of docker image names."""

import os

from typing import Dict, Union


class ImageName:
    """
    Docker image name abstraction.
    """

    DEFAULT_REGISTRY_ENDPOINT = os.environ.get(
        "DSV_DEFAULT_REGISTRY", "index.docker.io"
    )

    DEFAULT_REGISTRY_NAMESPACE = os.environ.get("DSV_DEFAULT_NAMESPACE", "library")

    DEFAULT_REGISTRY_TAG = os.environ.get("DSV_DEFAULT_TAG", "latest")

    def __init__(self, endpoint: Union[str, None], image: str, tag: str = None):
        """
        Args:
            endpoint: Endpoint address for fully qualified image names.
            image: Name of the image, optionally including a namespace.
            tag: Optional tag name.
        """
        self.endpoint = endpoint
        self.image = image
        self.tag = tag

    def __str__(self):
        result = self.image
        if self.tag:
            result = "{0}:{1}".format(result, self.tag)
        if self.endpoint:
            result = "{0}/{1}".format(self.endpoint, result)

        return result

    @staticmethod
    def _parse_string(string: str) -> Dict:
        """
        Parses the endpoint, image, and tag from a given string.

        Args:
            string: The string to be parsed.

        Returns:
            dict:
                endpoint: The registry endpoint; address with optional port.
                image: The name of the image; the image name and optional namespace.
                tag: The tag name.
        """
        result = {"endpoint": None, "image": None, "tag": None}

        segments = string.split("/")

        parts = segments[-1].split(":")
        result["image"] = parts[0]
        if len(parts) == 2:
            result["tag"] = parts[1]

        if len(segments) == 1:
            # image[:tag]
            pass
        elif len(segments) == 2:
            # host[:port]/image[:tag] OR namespace/image[:tag]

            # Note: https://docs.docker.com/engine/reference/commandline/tag/
            #
            #       An image name is made up of slash-separated name components, optionally prefixed by a registry
            #       hostname. The hostname must comply with standard DNS rules, but may not contain underscores. If a
            #       hostname is present, it may optionally be followed by a port number in the format :8080. ... Name
            #       components may contain lowercase letter, digits and separators. A separator is defined as a period,
            #       one or two underscores, or one or more dashes. A name component may not start or end with a
            #       separator. A tag name ... may contain lowercase and uppercase letters, digits, underscores, periods
            #       and dashes. A tag name may not start with a period or a dash ... .

            # Assumption: That endpoint addresses will contain at least one '.' (period) character, and by convention
            #             images namespaces will not.
            if ":" not in segments[0] and "." not in segments[0]:
                result["image"] = "{0}/{1}".format(segments[0], result["image"])
            else:
                result["endpoint"] = segments[0]
        elif len(segments) == 3:
            # host[:port]/namespace/image[:tag]
            result["endpoint"] = segments[0]
            result["image"] = "{0}/{1}".format(segments[1], result["image"])
        else:
            raise RuntimeError("Unable to parse string: {0}".format(string))

        return result

    @staticmethod
    def parse(image_name: str):
        """
        Initializes an ImageName from a given image name string.

        Args:
            image_name: String containing the image name to be parsed.

        Returns:
            The newly initialized object.
        """
        parsed = ImageName._parse_string(image_name)
        return ImageName(parsed["endpoint"], parsed["image"], parsed["tag"])

    def resolve_endpoint(self) -> str:
        """
        Resolves the registry endpoint.

        Returns:
            The explicit registry endpoint.
        """
        if self.endpoint:
            return self.endpoint

        return ImageName.DEFAULT_REGISTRY_ENDPOINT

    def resolve_image(self) -> str:
        """
        Resolves the name of the image.

        Returns:
            The explicit name of the image, with namespace.
        """

        segments = self.image.split("/")
        if len(segments) < 2:
            return "{0}/{1}".format(ImageName.DEFAULT_REGISTRY_NAMESPACE, self.image)

        return self.image

    def resolve_tag(self) -> str:
        """
        Retrieves resolves the tag name.

        Returns:
            The explicit tag name
        """
        if self.tag:
            return self.tag

        return ImageName.DEFAULT_REGISTRY_TAG
