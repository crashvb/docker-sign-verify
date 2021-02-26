#!/usr/bin/env python

"""Classes that provide signature functionality."""

import ast
import asyncio
import logging
import inspect
import io
import os
import subprocess

from pathlib import Path
from typing import Any

import aiofiles

from aiotempfile.aiotempfile import open as aiotempfile
from pretty_bad_protocol._meta import GPGBase
from pretty_bad_protocol._parsers import Verify

from .signer import Signer

LOGGER = logging.getLogger(__name__)


def _patch_pretty_bad_protocol():
    # pylint: disable=exec-used,protected-access,undefined-variable

    def getsource_dedented(obj):
        lines = inspect.getsource(obj).split("\n")
        indent = len(lines[0]) - len(lines[0].lstrip())
        return "\n".join(line[indent:] for line in lines)

    source = getsource_dedented(Verify._handle_status)
    node = ast.parse(source)

    # Change the function name ...
    node.body[0].name = "duck_punch__handle_status"

    # Change KEY_CONSIDERED processing by removing self.status from the join list ...
    #        FN      IF      ELSEIF    ELSEIF    Assign  join  List    Attribute
    del node.body[0].body[1].orelse[0].orelse[0].body[0].value.args[0].elts[0]
    # import astpretty
    # astpretty.pprint(node.body[0].body[1].orelse[0].orelse[0].body[0].value.args[0])

    # Define a the method, globally ...
    code = compile(node, __name__, "exec")
    exec(code, globals())

    # DUCK PUNCH: Override the class method
    Verify._handle_status = duck_punch__handle_status

    # TODO: Duck punch Verify._handle_status::KEYREVOKED to set self.value = False ...


class GPGSigner(Signer):
    """
    Creates and verifies docker image signatures using GnuPG.
    """

    class DuckPunchGPGBase:
        """Dummy class that doesn't do all the crap that GPGBase.__init__ does."""

        # pylint: disable=too-few-public-methods
        def __init__(self):
            self.ignore_homedir_permissions = False
            self.verbose = False

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
        # pylint: disable=protected-access
        """
        Invoke the GnuPG library parsing for status.

        Args:
            status: Status from GnuPG.

        Returns:
            The pretty_bad_protocol._parsers.Verify object.
        """
        result = Verify(None)
        GPGBase._read_response(
            GPGSigner.DuckPunchGPGBase(),
            io.TextIOWrapper(io.BytesIO(status), encoding="utf-8"),
            result,
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


_patch_pretty_bad_protocol()
