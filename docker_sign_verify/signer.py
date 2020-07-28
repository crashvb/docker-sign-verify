#!/usr/bin/env python

"""Classes that provide signature functionality."""

import abc
import logging

from typing import Any

from .exceptions import UnsupportedSignatureTypeError

LOGGER = logging.getLogger(__name__)


class Signer(abc.ABC):
    """
    Abstract class to create and verify docker image signatures.
    """

    @staticmethod
    def for_signature(signature: str) -> "Signer":
        """
        Retrieves a signer that can be used to verify a given signature value.

        Args:
            signature: The PEM encoded signature value for which to retrieve the signer.

        Returns:
            The corresponding signer.
        """
        result = None

        module = __import__(__package__)
        if "PGP SIGNATURE" in signature:
            result = getattr(module, "GPGSigner")()
        elif "PKI SIGNATURE" in signature:
            result = getattr(module, "PKISigner")()

        if not result:
            raise UnsupportedSignatureTypeError(signature=signature)

        return result

    @abc.abstractmethod
    async def sign(self, data: bytes) -> str:
        """
        Signs given data.

        Args:
            data: The data to be signed.

        Returns:
            A PEM encoded signature value.
        """

    @abc.abstractmethod
    async def verify(self, data: bytes, signature: str) -> Any:
        """
        Verifies data against a given signature.

        Args:
            data: The data to be verified.
            signature: The signature against which to verify the data.

        Returns:
            Signer-specific result value.
        """
