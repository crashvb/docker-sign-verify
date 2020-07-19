#!/usr/bin/env python

"""Classes that provide signature functionality."""

import logging
import io
import os
import tempfile

from pathlib import Path
from typing import Any

import gnupg

from .signer import Signer

LOGGER = logging.getLogger(__name__)


class GPGSigner(Signer):
    """
    Creates and verifies docker image signatures using GnuPG.
    """

    HOMEDIR = Path(os.environ.get("DSV_GPG_DATASTORE", Path.home().joinpath(".gnupg")))
    OPTIONS = os.environ.get("DSV_GPG_OPTIONS", "--pinentry-mode loopback")

    def __init__(
        self,
        *,
        keyid: str = None,
        passphrase: str = None,
        homedir: Path = None,
        **kwargs
    ):
        """
        Args:
            keyid: The GPG key identifier, only required for signing.
            passphrase: The passphrase used to unlock the GPG key.
            homedir: The GPG home directory (default: ~/.gnupg).
        """
        self.keyid = keyid
        self.passphrase = passphrase
        self.homedir = homedir if homedir else GPGSigner.HOMEDIR

        LOGGER.debug("Using trust store: %s", self.homedir)
        self.gpg = gnupg.GPG(
            homedir=self.homedir,
            ignore_homedir_permissions=True,
            options=[GPGSigner.OPTIONS],
            **kwargs
        )

    async def _debug_init_store(
        self, name: str = "DSV Test Key", email: str = "test@key.com"
    ):
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
        if not result:
            LOGGER.warning("GPG keystore generation failed!")
        self.keyid = str(result)

        return result

    # Signer Members

    # TODO: Convert to async
    async def sign(self, data: bytes) -> str:
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

    # TODO: Convert to async
    async def verify(self, data: bytes, signature: str) -> Any:
        # Note: gnupg.py:verify_file() forces sig_file to be on disk, as the
        #       underlying gpg utility does the same =(
        with tempfile.NamedTemporaryFile() as tmpfile:
            tmpfile.write(signature.encode("utf-8"))
            tmpfile.flush()
            os.fsync(tmpfile.fileno())
            return self.gpg.verify_file(io.BytesIO(data), tmpfile.name)
