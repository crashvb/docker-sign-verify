#!/usr/bin/env python

"""Classes that provide signature functionality."""

import asyncio
import logging
import io
import os
import subprocess
import types

from pathlib import Path
from typing import Any

import aiofiles

from gnupg._meta import GPGBase
from gnupg._parsers import Verify

from .aiotempfile import open as aiotempfile
from .signer import Signer

LOGGER = logging.getLogger(__name__)


class GPGSigner(Signer):
    """
    Creates and verifies docker image signatures using GnuPG.
    """

    def __init__(
        self,
        *,
        keyid: str = None,
        passphrase: str = None,
        homedir: Path = None,
    ):
        """
        Args:
            keyid: The GPG key identifier, only required for signing.
            passphrase: The passphrase used to unlock the GPG key.
            homedir: The GPG home directory (default: ~/.gnupg).
        """
        self.keyid = keyid
        self.passphrase = passphrase
        self.homedir = homedir
        if not self.homedir:
            gpg_datastore = os.environ.get("DSV_GPG_DATASTORE")
            if gpg_datastore:
                self.homedir = Path(gpg_datastore)
        if not self.homedir:
            self.homedir = Path.home().joinpath(".gnupg")
            LOGGER.warning("Using default GNUPGHOME: %s", self.homedir)
        self.homedir = Path(self.homedir)

        LOGGER.debug("Using trust store: %s", self.homedir)

    @staticmethod
    async def _parse_status(status: bytes) -> Verify:
        """
        Invoke the GnuPG library parsing for status.

        Args:
            status: Status from GnuPG.

        Returns:
            The gnupg._parsers.Verify object.
        """
        # DUCK PUNCH:
        # * Define a dummy class that doesn't do all the crap that GPGBase.__init__ does.
        # * Borrow the GPGBase._read_response method.
        class Dummy:
            # pylint: disable=missing-class-docstring,too-few-public-methods
            verbose: False

        # pylint: disable=protected-access
        setattr(
            Dummy,
            GPGBase._read_response.__name__,
            types.MethodType(GPGBase._read_response, Dummy),
        )

        result = Verify(None)
        # pylint: disable=no-member
        Dummy()._read_response(
            io.TextIOWrapper(io.BytesIO(status), encoding="utf-8"), result
        )
        return result

    # Signer Members

    async def sign(self, data: bytes) -> str:
        if not self.keyid:
            raise RuntimeError("Cannot sign without keyid!")
        if not self.passphrase or len(self.passphrase) < 1:
            raise RuntimeError("Refusing to use an unprotected key!")

        # Write the data to a temporary file and invoke GnuPG to create a detached signature ...
        signaturefile = None
        async with aiotempfile(mode="w+b") as datafile:
            signaturefile = Path(f"{datafile.name}.asc")

            # Write the data to a temporary file
            await datafile.write(data)
            await datafile.flush()

            args = [
                "gpg",
                "--no-options",
                "--no-emit-version",
                "--no-tty",
                "--status-fd",
                "2",
                "--homedir",
                str(self.homedir),
                "--batch",
                "--passphrase-fd",
                "0",
                "--sign",
                "--armor",
                "--detach-sign",
                "--default-key",
                str(self.keyid),
                "--digest-algo",
                "SHA512",
                "--pinentry-mode",
                "loopback",
                datafile.name,
            ]

            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await process.communicate(self.passphrase.encode("utf-8"))
            if process.returncode:
                LOGGER.debug(
                    "Command Failed:\nArgs: %s\n---stdout---\n%s\n---stderr---\n%s",
                    " ".join(args),
                    stdout.decode("utf-8"),
                    stderr.decode("utf-8"),
                )
                return ""

        # Retrieve the detached signature and cleanup ...
        try:
            async with aiofiles.open(signaturefile) as tmpfile:
                return await tmpfile.read()
        finally:
            signaturefile.unlink(missing_ok=True)

    async def verify(self, data: bytes, signature: str) -> Any:
        # Write the data and signature to temporary files and invoke GnuPG to verify they match ...
        async with aiotempfile(mode="w+b") as datafile:
            await datafile.write(data)
            await datafile.flush()
            async with aiotempfile(mode="w+b") as signaturefile:
                await signaturefile.write(signature.encode("utf-8"))
                await signaturefile.flush()

                args = [
                    "gpg",
                    "--no-options",
                    "--no-emit-version",
                    "--no-tty",
                    "--status-fd",
                    "2",
                    "--homedir",
                    str(self.homedir),
                    "--batch",
                    "--verify",
                    signaturefile.name,
                    datafile.name,
                ]

                process = await asyncio.create_subprocess_exec(
                    *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                _, stderr = await process.communicate()
                result = await GPGSigner._parse_status(stderr)

                return result
