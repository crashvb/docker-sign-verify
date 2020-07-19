#!/usr/bin/env python

# pylint: disable=too-few-public-methods

"""Reusable string literals."""

from typing import Any


class DigestMismatchError(ValueError):
    """Error raised when two compared digest values are not equal."""


class MalformedConfigurationError(ValueError):
    """Error raised when assertions about a configuration fail."""

    def __init__(
        self, message: str = "Configuration is malformed!", *, config: Any = None
    ):
        super().__init__(message)
        self.config = config


class NoSignatureError(RuntimeError):
    """Error raised when a signed image does not contain any signatures."""

    def __init__(
        self,
        message: str = "Image does not contain any signatures!",
        image_name: Any = None,
    ):
        super().__init__(message)
        self.image_name = image_name


class SignatureMismatchError(ValueError):
    """Error raised when the signature value for an images is invalid."""


class UnsupportedSignatureTypeError(RuntimeError):
    """Error raised when the type of an image signature cannot be derived."""

    def __init__(
        self, message: str = "Unsupported signature type!", *, signature: str = None
    ):
        super().__init__(message)
        self.signature = signature
