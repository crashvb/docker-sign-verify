#!/usr/bin/env python

"""
Abstraction of a docker image configuration, as defined in:

https://github.com/moby/moby/blob/master/image/spec/v1.md
(eventually, https://github.com/opencontainers/image-spec/blob/master/config.md)
"""

import copy
import json
import logging
import re

from typing import Dict

import canonicaljson

from .signers import Signer
from .utils import formatted_digest, must_be_equal, FormattedSHA256

LOGGER = logging.getLogger(__name__)


class ImageConfig:
    """
    Docker image configuration.
    """

    # Label containing the original config digest
    ORIGINAL_CONFIG_LABEL = "original_config"

    # Label containing PEM encoded signature(s) (newline concatenated)
    SIGNATURES_LABEL = "signatures"

    def __init__(self, config: bytes):
        """
        Args:
            config: The raw image configuration.
        """
        self._set_config(config)

    def __str__(self):
        # TODO: Remove me if tests work: return str(self.get_config())
        return self.get_config().decode("utf-8")

    def _construct_json_fragment(self) -> bytes:
        """
        Constructs the serialized signature data as a JSON fragment.

        Returns:
            The byte representation of the json fragment.
        """
        result = ""
        signature_data = self.get_signature_data()

        if signature_data["signatures"]:
            result += "{0}:{1},".format(
                json.dumps(ImageConfig.SIGNATURES_LABEL),
                json.dumps(signature_data["signatures"]),
            )
        if signature_data["original_config"]:
            result += "{0}:{1},".format(
                json.dumps(ImageConfig.ORIGINAL_CONFIG_LABEL),
                json.dumps(signature_data["original_config"]),
            )

        return result.encode("utf-8")

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

        if not config:
            raise RuntimeError(
                "Unable to locate [Cc]onfig key within image configuration!"
            )

        # TODO: Isolate which images are causing exceptions here, and add specific tests ...
        try:
            labels = config["Labels"]
        except KeyError:
            LOGGER.warning("Non-conformant image configuration; 'Labels' missing!")

        if labels is None:
            labels = config["Labels"] = {}

        return labels

    def _replace_signature_data(self):
        """
        Replaces the serialized signature data within an image configuration, preserving the original formatting.

        Note: This method does NOT detect and replace existing signature data; duplicates are possible!
        """
        raw_signature_data = self._construct_json_fragment()

        token_find = b'"Labels":{'
        token_replace = token_find + raw_signature_data
        if self.config.find(token_find) == -1:
            LOGGER.debug(
                "Unable to locate labels token with existing values; retrying with empty set ..."
            )
            token_find = b'"Labels":null'
            # Note: Remove trailing comma for empty set
            token_replace = b'"Labels":{' + raw_signature_data[:-1] + b"}"
        if self.config.find(token_find) == -1:
            raise RuntimeError("Unable to locate labels token!")
        self._set_config(self.config.replace(token_find, token_replace, 1))

    def _remove_signature_data(self) -> bytes:
        """
        Removes the serialized signature data from within image configuration, preserving the original formatting.

        Returns:
            bytes: as defined by :func:~docker_sign_verify.ImageConfig._construct_json_fragment.
        """
        raw_signature_data = self._construct_json_fragment()

        # Remove with trailing comma ...
        token_find = raw_signature_data
        token_replace = b""
        config = self.config.replace(token_find, token_replace, 1)

        # ... then without ...
        token_find = raw_signature_data[:-1]
        config = config.replace(token_find, token_replace, 1)

        # Remove empty labels ...
        token_find = b'"Labels":{}'
        token_replace = b'"Labels":null'
        config = config.replace(token_find, token_replace, 1)

        self._set_config(config)
        return raw_signature_data

    def _set_config(self, config: bytes):
        """
        Assigns the raw image configuration and updates the internal json object.

        Args:
            config: The raw image configuration.
        """
        self.config = config
        self.config_json = json.loads(self.config)

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
        for label in [ImageConfig.SIGNATURES_LABEL, ImageConfig.ORIGINAL_CONFIG_LABEL]:
            ImageConfig._get_labels(config_json).pop(label, None)

        return canonicaljson.encode_canonical_json(config_json)

    def get_config_digest(self) -> FormattedSHA256:
        """
        Retrieves the SHA256 digest value of the raw image configuration.

        Returns:
            The SHA256 digest value of the raw image configuration.
        """
        return formatted_digest(self.config)

    def get_config_digest_canonical(self) -> FormattedSHA256:
        """
        Retrieves the SHA256 digest value of the image configuration in canonical JSON form.

        Returns:
            The SHA256 digest value of the image configuration in canonical JSON form.
        """
        return formatted_digest(self.get_config_canonical())

    def get_image_layers(self) -> list:
        """
        Retrieves the listing of image layer identifiers.

        Returns:
            The listing of image layer identifiers.
        """
        diff_ids = self.config_json["rootfs"]["diff_ids"]
        return [FormattedSHA256.parse(x) for x in diff_ids]

    def get_signature_data(self):
        """
        Retrieves the signature data from the image configuration.

        Returns:
            dict:
                original_config: SHA256 digest value corresponding to the unsigned raw image configuration, or None.
                signatures: String of new line separated PEM encoded signature values.
                signatures_list: List of PEM encoded signature values.
        """
        labels = ImageConfig._get_labels(self.config_json)
        original_config = labels.get(ImageConfig.ORIGINAL_CONFIG_LABEL, None)
        signatures = labels.get(ImageConfig.SIGNATURES_LABEL, "")

        pem_marker = r"-{5}[^-]+-{5}"
        signature_list = re.findall(r"({0}[^-]+{0})".format(pem_marker), signatures)

        return {
            "original_config": original_config,
            "signatures": signatures,
            "signature_list": signature_list,
        }

    def set_signature_data(self, original_config: str = None, signatures: str = None):
        """
        Assigns the signature data to the image configuration.

        Args:
            original_config: SHA256 digest value corresponding to the unsigned raw image configuration.
            signatures: String of new line separated PEM encoded signature values.
        """
        self._remove_signature_data()

        labels = ImageConfig._get_labels(self.config_json)
        if original_config is not None:
            labels[ImageConfig.ORIGINAL_CONFIG_LABEL] = original_config
        else:
            labels.pop(ImageConfig.ORIGINAL_CONFIG_LABEL, None)

        if signatures is not None:
            labels[ImageConfig.SIGNATURES_LABEL] = signatures
        else:
            labels.pop(ImageConfig.SIGNATURES_LABEL, None)

        self._replace_signature_data()

    def sign(self, signer: Signer) -> str:
        """
        Signs the SHA256 digest value of image configuration in canonical JSON form, and appends it to the signature
        list.

        Args:
            signer: The signer used to create the signature value.

        Returns:
            The PEM encoded signature value.
        """

        # TODO: Consider moving the validation logic below to a low-level check_signatures() method

        signature_data = self.get_signature_data()
        original_config = signature_data.get("original_config", None)
        if signature_data["signatures"]:
            signature_data["signatures"] += "\n"

            # It is not reasonably possible to reproduce the hash of the
            # original image configuration at this point.
            if not original_config:
                raise RuntimeError(
                    "Refusing to sign; signature(s) exist without original config hash!"
                )
        else:
            if original_config:
                LOGGER.warning(
                    "Original config hash found without signatures;overriding!"
                )
            original_config = self.get_config_digest()

        digest = self.get_config_digest_canonical().encode("utf-8")
        # if original_config and digest != original_config:
        #    raise RuntimeError("Refusing to sign; embedded and calculated original config values are inconsistent!")

        signature = signer.sign(digest)
        if not signature:
            raise RuntimeError("Failed to create signature!")
        signature_data["signatures"] += signature
        self.set_signature_data(original_config, signature_data["signatures"])

        return signature

    def verify_signatures(self):
        """
        Verifies the PEM encoded signature values in the image configuration.

        Returns:
            dict:
                signature_data: Dictionary as defined by :func:~docker_sign_verify.ImageConfig.get_signature_data.
                results: Signer-specific result value.
        """
        signature_data = self.get_signature_data()
        if not signature_data["signature_list"]:
            raise RuntimeError("Image does not contain any signatures!")

        # Remove the signatures and verify the original image configuration ...
        config_original = copy.deepcopy(self)
        config_original._remove_signature_data()
        must_be_equal(
            signature_data["original_config"],
            config_original.get_config_digest(),
            "Image config digest mismatch (2)",
        )

        # Verify the image signatures ...
        digest = config_original.get_config_digest_canonical().encode("utf-8")
        results = []
        for signature in signature_data["signature_list"]:
            signer = Signer.for_signature(signature)
            result = signer.verify(digest, signature)
            results.append(result)

        return {"signature_data": signature_data, "results": results}

    def unsign(self):
        """Removes all signatures fro the image configuration."""
        self._remove_signature_data()
