#!/usr/bin/env python

"""
Abstraction of a docker image configuration, as defined in:

https://github.com/moby/moby/blob/master/image/spec/v1.md
(eventually, https://github.com/opencontainers/image-spec/blob/master/config.md)
"""

import json
import logging

from typing import Any, Dict, List, TypedDict

import canonicaljson

from docker_registry_client_async import FormattedSHA256, JsonBytes
from docker_registry_client_async.utils import must_be_equal

from .exceptions import (
    DigestMismatchError,
    MalformedConfigurationError,
    NoSignatureError,
)
from .signer import Signer
from .specs import SignatureTypes

LOGGER = logging.getLogger(__name__)


class ImageConfigSignatureEntry(TypedDict):
    # pylint: disable=missing-class-docstring
    digest: FormattedSHA256
    signature: str


class ImageConfigVerifySignatures(TypedDict):
    # pylint: disable=missing-class-docstring
    signatures: List[ImageConfigSignatureEntry]
    results: List[Any]


class ImageConfig(JsonBytes):
    """
    Docker image configuration.
    """

    # Label containing a string value (escaped json)
    SIGNATURES_LABEL = "signatures"

    # The normalized empty signature value
    DEFAULT_SIGNATURES_VALUE = "[]"

    def __init__(self, config: bytes):
        # pylint: disable=useless-super-delegation
        """
        Args:
            config: The raw image configuration.
        """
        super().__init__(config)

    @staticmethod
    def _get_labels(config_json) -> Dict[str, str]:
        """
        Retrieves the "Labels" dictionary from the given image configuration.

        Args:
            config_json: The image configuration from which to retrieve the dictionary.

        Returns:
            dict: The corresponding dictionary, or an empty dictionary if NoneType.
        """

        # Note: We need to handle both key cases, as Red Hat does not conform to the standard.
        try:
            config = config_json["Config"]
        except KeyError:
            config = config_json["config"]

        if config is None:
            raise MalformedConfigurationError(
                "Unable to locate [Cc]onfig key within image configuration!",
                config=config_json,
            )

        try:
            labels = config["Labels"]
        except KeyError:
            labels = None
            LOGGER.debug("Non-conformant image configuration; 'Labels' missing!")

        if labels is None:
            labels = config["Labels"] = {}

        return labels

    @staticmethod
    def _normalize(config_json):
        """
        Normalizes a given image configuration so that it contains, at a minimum, the signatures label.

        Args:
            config_json: The image configuration to be normalized.

        Returns:
            The normalized image configuration.
        """
        labels = ImageConfig._get_labels(config_json)
        signatures = labels.get(
            ImageConfig.SIGNATURES_LABEL, ImageConfig.DEFAULT_SIGNATURES_VALUE
        )
        labels[ImageConfig.SIGNATURES_LABEL] = signatures

        return config_json

    def get_bytes_canonical(self) -> bytes:
        """
        Retrieves the image configuration in canonical JSON form.

        Returns:
            The image configuration in canonical JSON form.
        """
        config_json = ImageConfig._normalize(self.get_json())
        return canonicaljson.encode_canonical_json(config_json)

    def get_digest_canonical(self) -> FormattedSHA256:
        """
        Retrieves the SHA256 digest value of the image configuration in canonical JSON form.

        Returns:
            The SHA256 digest value of the image configuration in canonical JSON form.
        """
        return FormattedSHA256.calculate(self.get_bytes_canonical())

    def get_image_layers(self) -> List[FormattedSHA256]:
        """
        Retrieves the listing of image layer identifiers.

        Returns:
            The listing of image layer identifiers.
        """
        # Note: We need to handle both key cases, as Microsoft does not conform to the standard.
        try:
            rootfs = self.get_json()["rootfs"]
        except KeyError:
            rootfs = self.get_json()["rootfS"]

        if rootfs is None:
            raise MalformedConfigurationError(
                "Unable to locate rootf[Ss] key within image configuration!",
                config=self,
            )

        diff_ids = rootfs["diff_ids"]
        return [FormattedSHA256.parse(x) for x in diff_ids]

    def clear_signature_list(self):
        """Helper method to remove all signatures from the image configuration."""
        self.set_signature_list([])

    def get_signature_list(self) -> List[ImageConfigSignatureEntry]:
        """
        Retrieves the signature list from the image configuration.

        Example format:
        [
          { "digest":"sha256:0123456789",
            "signature":"<sigvalue1>"
          },
          { "digest":"sha256:9876543210",
            "signature":"<sigvalue2>"
          },
          ...
        ]

        Returns:
            The deserialized / unescaped signature list in JSON form.
        """
        labels = ImageConfig._get_labels(self.get_json())
        return json.loads(
            labels.get(
                ImageConfig.SIGNATURES_LABEL, ImageConfig.DEFAULT_SIGNATURES_VALUE
            )
        )

    def set_signature_list(self, signatures: List[ImageConfigSignatureEntry]):
        """
        Serializes / escapes and assigns signature list to the image configuration. The method modifies the raw image
        configuration.

        Args:
            signatures: The deserialized / unescaped signature list in JSON form.
        """
        _json = self.get_json()
        labels = ImageConfig._get_labels(_json)
        labels[ImageConfig.SIGNATURES_LABEL] = json.dumps(signatures)
        self._set_json(_json)

    async def sign(
        self, signer: Signer, signature_type: SignatureTypes = SignatureTypes.SIGN
    ) -> str:
        """
        Signs or endorses the SHA256 digest value of image configuration, in canonical JSON form, and appends it to the
        signature list.

        (Co-)signatures remove all existing signatures before calculating the canonical digest; endorsements do not.
        Co-endorsements are not supported; however, nested endorsements are supported.

        Effectively, this allows for interlacing (co-)signatures and endorsements, where all (co-)signatures apply to a
        single, signature-less, image configuration regardless of where they appear in the signature list. And all
        endorsements apply to the image configuration with signatures order 0 through n-1 (where n is the order of
        endorsement being verified); regardless of what signatures or endorsements were added afterwards.

        Args:
            signer: The signer used to create the signature value.
            signature_type: Specifies what type of signature action to perform.

        Returns:
            The signature value as defined by :func:~docker_sign_verify.Signers.sign.
        """
        signatures = self.get_signature_list()
        if signature_type != SignatureTypes.ENDORSE:
            self.clear_signature_list()
        digest = self.get_digest_canonical()
        signature = await signer.sign(digest.encode("utf-8"))
        if not signature:
            raise RuntimeError("Failed to create signature!")

        entry = {"digest": digest, "signature": signature}
        if signature_type == SignatureTypes.RESIGN:
            signatures = [entry]
        else:
            signatures.append(entry)
        self.set_signature_list(signatures)

        return signature

    async def verify_signatures(self) -> ImageConfigVerifySignatures:
        """
        Verifies the PEM encoded signature values in the image configuration.

        Returns:
            dict:
                signature_data: List as defined by :func:~docker_sign_verify.ImageConfig.get_signature_list.
                results: Signer-specific result value.
        """
        signatures = self.get_signature_list()
        if not signatures:
            raise NoSignatureError()

        # Assumptions:
        # * The signature list is ordered.
        # * The first entry in the list *must* be a (co-)signature, as there is nothing older to endorse.
        # * Normalization during canonicalization ensures a consistent empty set.

        results = []
        for i, signature in enumerate(signatures):
            _temp = self.clone()
            # (Co-)signature
            if signature["digest"] == signatures[0]["digest"]:
                _temp.clear_signature_list()
            # Endorsement
            else:
                _temp.set_signature_list(signatures[:i])

            digest = _temp.get_digest_canonical()
            must_be_equal(
                signature["digest"],
                digest,
                "Image config canonical digest mismatch",
                error_type=DigestMismatchError,
            )

            signer = Signer.for_signature(signature["signature"])
            result = await signer.verify(digest.encode("utf-8"), signature["signature"])
            results.append(result)

        return {"signatures": signatures, "results": results}
