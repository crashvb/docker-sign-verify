#!/usr/bin/env python

"""
Abstraction of a docker image configuration, as defined in:

https://github.com/moby/moby/blob/master/image/spec/v1.md
(eventually, https://github.com/opencontainers/image-spec/blob/master/config.md)
"""

import copy
import json
import logging

from typing import Dict, List

import canonicaljson

from .signers import Signer
from .utils import formatted_digest, must_be_equal, FormattedSHA256

LOGGER = logging.getLogger(__name__)


class ImageConfig:
    """
    Docker image configuration.
    """

    # Label containing a string value (escaped json)
    SIGNATURES_LABEL = "signatures"

    # The normalized empty signature value
    DEFAULT_SIGNATURES_VALUE = "[]"

    def __init__(self, config: bytes):
        """
        Args:
            config: The raw image configuration.
        """
        self.config = self.config_json = None
        self._set_config(config)

    def __str__(self):
        return self.get_config().decode("utf-8")

    @staticmethod
    def _get_labels(config_json) -> Dict:
        """
        Retrieves the "Labels" dictionary from the given image configuration.

        Args:
            config_json: The image configuration from which to retrieve the dictionary.

        Returns:
            Dict: The corresponding dictionary, or an empty dictionary if NoneType.
        """

        # Note: We need to handle both key cases, as Red Hat does not conform to the standard.
        try:
            config = config_json["Config"]
        except KeyError:
            config = config_json["config"]

        if config is None:
            raise RuntimeError(
                "Unable to locate [Cc]onfig key within image configuration!"
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

    def _set_config(self, config: bytes):
        """
        Assigns the raw image configuration and updates the internal JSON object.

        Args:
            config: The raw image configuration.
        """
        self.config = config
        # Note: Do not normalize here, or integrity verification of unsigned images will fail.
        self.config_json = json.loads(self.config)

    def _set_config_json(self, config_json):
        """
        Assigns the internal JSON object and updates the raw image configuration.

        Args:
            config_json: The internal JSON object.
        """
        self.config_json = config_json
        self.config = json.dumps(self.config_json).encode("utf-8")

    def get_config(self) -> bytes:
        """
        Retrieves the raw image configuration.

        Returns:
            The raw image configuration.
        """
        return self.config

    def get_config_canonical(self):
        """
        Retrieves the image configuration in canonical JSON form.

        Returns:
            The image configuration in canonical JSON form.
        """
        config_json = copy.deepcopy(self.config_json)
        config_json = ImageConfig._normalize(config_json)
        return canonicaljson.encode_canonical_json(config_json)

    def get_config_digest(self) -> FormattedSHA256:
        """
        Retrieves the SHA256 digest value of the raw image configuration.

        Returns:
            The SHA256 digest value of the raw image configuration.
        """
        return formatted_digest(self.get_config())

    def get_config_digest_canonical(self) -> FormattedSHA256:
        """
        Retrieves the SHA256 digest value of the image configuration in canonical JSON form.

        Returns:
            The SHA256 digest value of the image configuration in canonical JSON form.
        """
        return formatted_digest(self.get_config_canonical())

    def get_image_layers(self) -> List:
        """
        Retrieves the listing of image layer identifiers.

        Returns:
            The listing of image layer identifiers.
        """
        diff_ids = self.config_json["rootfs"]["diff_ids"]
        return [FormattedSHA256.parse(x) for x in diff_ids]

    def clear_signature_list(self):
        """Helper method to remove all signatures from the image configuration."""
        self.set_signature_list([])

    def get_signature_list(self) -> List:
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
        labels = ImageConfig._get_labels(self.config_json)
        return json.loads(
            labels.get(
                ImageConfig.SIGNATURES_LABEL, ImageConfig.DEFAULT_SIGNATURES_VALUE
            )
        )

    def set_signature_list(self, signatures: List):
        """
        Serializes / escapes and assigns signature list to the image configuration. The method modifies the raw image
        configuration.

        Args:
            signatures: The deserialized / unescaped signature list in JSON form.
        """
        labels = ImageConfig._get_labels(self.config_json)
        labels[ImageConfig.SIGNATURES_LABEL] = json.dumps(signatures)
        self._set_config_json(self.config_json)

    def sign(self, signer: Signer, endorse: bool = False) -> str:
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
            endorse: Toggles between signing (default), and endorsing.

        Returns:
            The signature value as defined by :func:~docker_sign_verify.Signers.sign.
        """
        signatures = self.get_signature_list()
        if not endorse:
            self.clear_signature_list()
        digest = self.get_config_digest_canonical()
        signature = signer.sign(digest.encode("utf-8"))
        if not signature:
            raise RuntimeError("Failed to create signature!")

        signatures.append({"digest": digest, "signature": signature})
        self.set_signature_list(signatures)

        return signature

    def verify_signatures(self) -> Dict:
        """
        Verifies the PEM encoded signature values in the image configuration.

        Returns:
            dict:
                signature_data: List as defined by :func:~docker_sign_verify.ImageConfig.get_signature_list.
                results: Signer-specific result value.
        """
        signatures = self.get_signature_list()
        if not signatures:
            raise RuntimeError("Image does not contain any signatures!")

        # Assumptions:
        # * The signature list is ordered.
        # * The first entry in the list *must* be a (co-)signature, as there is nothing older to endorse.
        # * Normalization during canonicalization ensures a consistent empty set.

        results = []
        for i, signature in enumerate(signatures):
            _temp = copy.deepcopy(self)
            # (Co-)signature
            if signature["digest"] == signatures[0]["digest"]:
                _temp.clear_signature_list()
            # Endorsement
            else:
                _temp.set_signature_list(signatures[:i])

            digest = _temp.get_config_digest_canonical()
            must_be_equal(
                signature["digest"], digest, "Image config canonical digest mismatch"
            )

            signer = Signer.for_signature(signature["signature"])
            result = signer.verify(digest.encode("utf-8"), signature["signature"])
            results.append(result)

        return {"signatures": signatures, "results": results}
