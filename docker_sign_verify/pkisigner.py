#!/usr/bin/env python

"""Classes that provide signature functionality."""

import base64
import logging
import os
import re

from pathlib import Path
from typing import Any, List

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256


from .signer import Signer

LOGGER = logging.getLogger(__name__)


# https://pysheeet.readthedocs.io/en/latest/notes/python-security.html
class PKISigner(Signer):
    """
    Creates and verifies docker image signatures using OpenSSL.
    """

    KEYPAIR = os.environ.get("DSV_PKI_DATASTORE", Path.home().joinpath("dsv.pem"))

    TAG_START = "-----BEGIN PKI SIGNATURE-----"
    TAG_END = "-----END PKI SIGNATURE-----"

    def __init__(self, *, keypair_path=KEYPAIR, passphrase: str = None):
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

    async def _debug_init_keypair(self, bits: int = 4096):
        """
        Initializes a new PKI certificate pair.

        Args:
            bits: Entropy to use when generating the private key.
        """
        key = RSA.generate(bits)
        private_key = key.export_key(passphrase=self.passphrase)
        public_key = key.publickey().export_key()

        # TODO: Convert to async
        with open(self.keypair_path, "wb") as file:
            file.write(public_key)
            file.write(os.linesep.encode("utf-8"))
            file.write(private_key)
            file.flush()

    async def get_keypair(self) -> List:
        """
        Retrieves the keypair entries from disk.

        Returns:
            The list of PEM encoded entries.
        """
        # TODO: Convert to generator (yield) and refactor get_private_signer and get_public_signer to use "async for"
        #       instead ...
        if self.keypair_entries is None:
            # TODO: Convert to async
            with open(self.keypair_path, "r") as file:
                content = file.read()
            self.keypair_entries = re.findall(
                r"(-{5}BEGIN([^-]+)-{5}.+-{5}END\2-{5})", content, re.DOTALL
            )
            self.keypair_entries = [x[0] for x in self.keypair_entries]
        return self.keypair_entries

    async def get_private_signer(self) -> PKCS115_SigScheme:
        """
        Retrieves a private signer, initialized from the first PEM encoded private key entry.

        Returns:
            A private signer initialized from the first PEM encoded private key entry.
        """
        if not self.private_signer:
            for entry in await self.get_keypair():
                if "RSA PRIVATE KEY" in entry:
                    private_rsa_key = RSA.import_key(entry, self.passphrase)
                    self.private_signer = pkcs1_15.new(private_rsa_key)
        return self.private_signer

    async def get_public_signer(self) -> PKCS115_SigScheme:
        """
        Retrieves a public signer, initialized from the first PEM encoded public key entry.

        Returns:
            A public signer, initialized from the first PEM encoded public key entry.
        """
        if not self.public_signer:
            for entry in await self.get_keypair():
                if "CERTIFICATE" in entry or "PUBLIC KEY" in entry:
                    # TODO: Collect x509 certificate details
                    # TODO: Is it possible to use OS-level cacerts instead of providing the public key?
                    public_rsa_key = RSA.import_key(entry)
                    self.public_signer = pkcs1_15.new(public_rsa_key)
        return self.public_signer

    # Signer Members

    async def sign(self, data: bytes) -> str:
        digest = SHA256.new(data)
        private_signer = await self.get_private_signer()
        raw_signature = private_signer.sign(digest)

        return "{0}\n\n{1}\n{2}".format(
            PKISigner.TAG_START,
            base64.b64encode(raw_signature).decode(),
            PKISigner.TAG_END,
        )

    async def verify(self, data: bytes, signature: str) -> Any:
        # if not self.public_key_path:
        #    raise RuntimeError("Cannot verify without public key!")
        buffer = base64.b64decode(signature.split()[3])

        digest = SHA256.new(data)
        # pylint: disable=not-callable
        valid = False
        try:
            public_signer = await self.get_public_signer()
            public_signer.verify(digest, buffer)
            valid = True
        except ValueError:
            ...

        # TODO: Refactor this to be a class that is similar to what GPG returns, and update
        #       imagesource.verify_image_signatures to refelect the changes.
        return {"keypair_path": self.keypair_path, "type": "pki", "valid": valid}
