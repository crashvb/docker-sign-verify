#!/usr/bin/env python

"""Classes that provide signature functionality."""

# TODO: Update pycharm version and test
# from __future__ import annotations

import abc
import base64
import logging
import io
import os
import re
import tempfile

from pathlib import Path
from typing import List

import gnupg

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256

LOGGER = logging.getLogger(__name__)


class Signer(abc.ABC):
    """
    Abstract class to create and verify docker image signatures.
    """

    @staticmethod
    def for_signature(signature: str):
        """
        Retrieves a signer that can be used to verify a given signature value.

        Args:
            signature: The PEM encoded signature value for which to retrieve the signer.

        Returns:
            The corresponding signer.
        """
        result = None

        if "PGP SIGNATURE" in signature:
            result = GPGSigner()
        elif "PKI SIGNATURE" in signature:
            result = PKISigner()

        if not result:
            raise RuntimeError("Unsupported signature type!")

        return result

    @abc.abstractmethod
    def sign(self, data: bytes) -> str:
        """
        Signs given data.

        Args:
            data: The data to be signed.

        Returns:
            A PEM encoded signature value.
        """

    @abc.abstractmethod
    def verify(self, data: bytes, signature: bytes):
        """
        Verifies data against a given signature.

        Args:
            data: The data to be verified.
            signature: The signature against which to verify the data.

        Returns:
            Signer-specific result value.
        """


class GPGSigner(Signer):
    """
    Creates and verifies docker image signatures using GnuPG.
    """

    HOMEDIR = os.environ.get("DSV_GPG_DATASTORE", Path.home().joinpath(".gnupg"))

    def __init__(self, keyid=None, passphrase=None, homedir=HOMEDIR):
        """
        Args:
            keyid: The GPG key identifier, only required for signing.
            passphrase: The passphrase used to unlock the GPG key.
            homedir: The GPG home directory (default: ~/.gnupg).
        """
        self.keyid = keyid
        self.passphrase = passphrase

        LOGGER.debug("Using trust store: %s", homedir)
        self.gpg = gnupg.GPG(homedir=homedir)

    def _debug_init_store(self, name="DSV Test Key", email="test@key.com"):
        """
        Initializes a new GPG keystore for testing purposes.

        Args:
            name: GPG identity name used to create the new key.
            email: GPG identity email used to create the new key.

        Returns:
            The GPG key identifier of the newly created key.
        """
        input_data = self.gpg.gen_key_input(
            name_email=name, name_real=email, passphrase=self.passphrase
        )

        result = self.gpg.gen_key(input_data)
        self.keyid = str(result)

        return result

    # Signer Members

    def sign(self, data: bytes) -> str:
        if not self.keyid:
            LOGGER.warning("Signing using implicit / default keyid!")
            # raise RuntimeError("Cannot sign without keyid!")

        kwargs = {}
        if self.keyid:
            kwargs = {"default_key": self.keyid}

        result = self.gpg.sign(
            data, clearsign=False, detach=True, passphrase=self.passphrase, **kwargs
        )

        return str(result).rstrip()

    def verify(self, data: bytes, signature: str):
        # Note: gnupg.py:verify_file() forces sig_file to be on disk, as the
        #       underlying gpg utility does the same =(
        with tempfile.NamedTemporaryFile() as tmpfile:
            tmpfile.write(signature.encode("utf-8"))
            tmpfile.flush()
            os.fsync(tmpfile.fileno())
            return self.gpg.verify_file(io.BytesIO(data), tmpfile.name)


# https://pysheeet.readthedocs.io/en/latest/notes/python-security.html
class PKISigner(Signer):
    """
    Creates and verifies docker image signatures using OpenSSL.
    """

    KEYPAIR = os.environ.get("DSV_PKI_DATASTORE", Path.home().joinpath("dsv.pem"))

    TAG_START = "-----BEGIN PKI SIGNATURE-----"
    TAG_END = "-----END PKI SIGNATURE-----"

    def __init__(self, keypair_path=KEYPAIR, passphrase=None):
        """
        Reference: https://www.digicert.com/ssl-support/pem-ssl-creation.htm
        Args:
            keypair_path: Path to a file containing the entire trust chain and private key, PEM encoded.
            passphrase: The passphrase used to unlock the private key.
        """
        self.keypair_entries = None
        self.keypair_path = keypair_path
        self.passphrase = passphrase
        self.private_signer = None
        self.public_signer = None

        LOGGER.debug("Using keypair: %s", self.keypair_path)

    def _debug_init_keypair(self, bits=2048):
        """
        Initializes a new PKI certificate pair.

        Args:
            bits: Entropy to use when generating the private key.
        """
        key = RSA.generate(bits)
        private_key = key.export_key(passphrase=self.passphrase)
        public_key = key.publickey().export_key()

        with open(self.keypair_path, "wb") as file:
            file.write(public_key)
            file.write(os.linesep.encode("utf-8"))
            file.write(private_key)
            file.flush()

    def get_keypair(self) -> List:
        """
        Retrieves the keypair entries from disk.

        Returns:
            The list of PEM encoded entries.
        """
        if self.keypair_entries is None:
            with open(self.keypair_path, "r") as file:
                content = file.read()
            self.keypair_entries = re.findall(
                r"(-{5}BEGIN([^-]+)-{5}.+-{5}END\2-{5})", content, re.DOTALL
            )
            self.keypair_entries = [x[0] for x in self.keypair_entries]
        return self.keypair_entries

    def get_private_signer(self) -> PKCS115_SigScheme:
        """
        Retrieves a private signer, initialized from the first PEM encoded private key entry.

        Returns:
            A private signer initialized from the first PEM encoded private key entry.
        """
        if not self.private_signer:
            for entry in self.get_keypair():
                if "RSA PRIVATE KEY" in entry:
                    private_rsa_key = RSA.import_key(entry, self.passphrase)
                    self.private_signer = PKCS1_v1_5.new(private_rsa_key)
        return self.private_signer

    def get_public_signer(self) -> PKCS115_SigScheme:
        """
        Retrieves a public signer, initialized from the first PEM encoded public key entry.

        Returns:
            A public signer, initialized from the first PEM encoded public key entry.
        """
        if not self.public_signer:
            for entry in self.get_keypair():
                if "CERTIFICATE" in entry or "PUBLIC KEY" in entry:
                    # TODO: Collect x509 certificate details
                    # TODO: Is it possible to use OS-level cacerts instead of providing the public key?
                    public_rsa_key = RSA.import_key(entry)
                    self.public_signer = PKCS1_v1_5.new(public_rsa_key)
        return self.public_signer

    # Signer Members

    def sign(self, data: bytes) -> str:
        digest = SHA256.new(data)
        raw_signature = self.get_private_signer().sign(digest)

        return "{0}\n\n{1}\n{2}".format(
            PKISigner.TAG_START,
            base64.b64encode(raw_signature).decode(),
            PKISigner.TAG_END,
        )

    def verify(self, data: bytes, signature: str):
        # if not self.public_key_path:
        #    raise RuntimeError("Cannot verify without public key!")
        buffer = base64.b64decode(signature.split()[3])

        digest = SHA256.new(data)
        # pylint: disable=not-callable
        valid = False
        try:
            self.get_public_signer().verify(digest, buffer)
            valid = True
        except ValueError:
            ...

        return {"keypair_path": self.keypair_path, "type": "pki", "valid": valid}
