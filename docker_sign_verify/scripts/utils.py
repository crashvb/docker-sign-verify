#!/usr/bin/env python

"""Utility classes."""


from docker_registry_client_async import ImageName


# pylint: disable=unused-argument
def to_image_name(context, param, value: str) -> ImageName:
    """Converts an docker image name to an ImageName."""
    if isinstance(value, str):
        result = ImageName.parse(value)
    else:
        result = [ImageName.parse(v) for v in value]
    return result


# pylint: disable=too-few-public-methods
class HiddenPassword:
    """Helper class to mask password input."""

    def __init__(self, password: str = ""):
        """
        Args:
            password: The password.
        """
        self.password = password

    def __len__(self):
        return len(self.password)

    def __str__(self):
        return "*" * len(self.password)
