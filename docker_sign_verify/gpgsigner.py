#!/usr/bin/env python

"""Classes that provide signature functionality."""

import asyncio
import logging
import os
import subprocess
import time
import re

from enum import Enum
from pathlib import Path
from typing import NamedTuple, Optional

import aiofiles

from aiotempfile.aiotempfile import open as aiotempfile

from .signer import Signer

LOGGER = logging.getLogger(__name__)
PATTERN_BADSIG = re.compile(
    r"^\[GNUPG:\]\s+BADSIG\s+(?P<key_id>\S+)\s+(?P<username>.+)", flags=re.MULTILINE
)
PATTERN_GOODSIG = re.compile(
    r"^\[GNUPG:\]\s+GOODSIG\s+(?P<key_id>\S+)\s+(?P<username>.+)", flags=re.MULTILINE
)
PATTERN_NO_PUBKEY = re.compile(
    r"^\[GNUPG:\]\s+NO_PUBKEY\s+(?P<key_id>\S+)", flags=re.MULTILINE
)
PATTERN_TRUST = re.compile(r"^\[GNUPG:\]\s+TRUST_(?P<trust>\S+).*", flags=re.MULTILINE)
PATTERN_VALIDSIG = re.compile(
    r"^\[GNUPG:\]\s+VALIDSIG\s+(?P<fingerprint>\S+)\s+(?P<creation_date>\S+)\s+(?P<sig_timestamp>\S+)\s+"
    r"(?P<expire_timestamp>\S+).+(?P<pubkey_fingerprint>\S+)",
    flags=re.MULTILINE,
)


class GPGExecuteCommand(NamedTuple):
    # pylint: disable=missing-class-docstring
    returncode: int
    stderr: bytes
    stdout: bytes


# Attempt to be compatible with 'pretty-bad-protocol._parsers::Verify', as it is the defacto python standard for GnuPG.
class GPGStatus(Enum):
    # pylint: disable=missing-class-docstring
    BADSIG = "signature bad"
    GOODSIG = "signature good"
    NO_PUBKEY = "no public key"
    UNDEFINED = "signature undefined"
    VALIDSIG = "signature valid"


# Intentionally sorted to prevent people from directly comparing the "trustworthiness" of keys.
# In the "default" ordering, TRUST_NEVER would be "more trusted" than TRUST_UNDEFINED!
class GPGTrust(Enum):
    # pylint: disable=missing-class-docstring
    FULLY = "trust fully"
    MARGINAL = "trust marginal"
    NEVER = "trust never"
    ULTIMATE = "trust ultimate"
    UNDEFINED = "trust undefined"


class GPGSignerStatus(NamedTuple):
    # pylint: disable=missing-class-docstring
    fingerprint: str
    key_id: str
    status: GPGStatus
    timestamp: str
    trust: GPGTrust
    username: str


class GPGSignerVerify(NamedTuple):
    # pylint: disable=missing-class-docstring
    fingerprint: str
    key_id: str
    signer_long: Optional[str]
    signer_short: Optional[str]
    status: str
    timestamp: str
    trust: str
    type: str
    username: str
    valid: bool


class GPGSigner(Signer):
    """
    Creates and verifies docker image signatures using GnuPG.
    """

    def __init__(
        self,
        *,
        homedir: Path = None,
        keyid: str = None,
        passphrase: str = None,
    ):
        """
        Args:
            keyid: The GPG key identifier, only required for signing.
            passphrase: The passphrase used to unlock the GPG key.
            homedir: The GPG home directory (default: ~/.gnupg).
        """
        self.homedir = homedir
        if not self.homedir:
            gpg_datastore = os.environ.get("DSV_GPG_DATASTORE")
            if gpg_datastore:
                self.homedir = Path(gpg_datastore)
        if not self.homedir:
            gnupghome = os.environ.get("GNUPGHOME")
            if gnupghome:
                self.homedir = Path(gnupghome)
        if not self.homedir:
            self.homedir = Path.home().joinpath(".gnupg")
            LOGGER.warning("Using default GNUPGHOME: %s", self.homedir)
        self.homedir = Path(self.homedir)
        self.keyid = keyid
        self.log_gnupg_errors = bool(os.environ.get("DSV_GPG_LOG_ERRORS"))
        self.passphrase = passphrase

        LOGGER.debug("Using trust store: %s", self.homedir)

    @staticmethod
    async def _parse_output(*, output: bytes) -> GPGSignerStatus:
        """
        Extracting valid signatures from the output of GnuPG is like trying to fish your wallet out of a porta
        potty ... *something* good might come of it, but nobody would call it 'a success'!

        Args:
            status: Status from GnuPG.

        Returns:
            The parsed status.
        """
        fingerprint = None
        key_id = None
        status = GPGStatus.UNDEFINED
        timestamp = None
        trust = GPGTrust.UNDEFINED
        username = None

        string = output.decode("utf-8")

        # The ordering of the pattern matches is significant ...
        # https://www.gnupg.org/documentation/manuals/gnupg/Automated-signature-checking.html

        match = PATTERN_GOODSIG.search(string=string)
        if match:
            key_id = match.group("key_id")
            username = match.group("username")
            status = GPGStatus.GOODSIG

        match = PATTERN_TRUST.search(string=string)
        if match:
            trust = GPGTrust[match.group("trust").upper()]

        match = PATTERN_VALIDSIG.search(string=string)
        if match:
            fingerprint = match.group("fingerprint")
            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(float(match.group("sig_timestamp")))
            )
            status = GPGStatus.VALIDSIG

        # These should go last to stomp values ...

        match = PATTERN_BADSIG.search(string=string)
        if match:
            key_id = match.group("key_id")
            username = match.group("username")
            status = GPGStatus.BADSIG

        match = PATTERN_NO_PUBKEY.search(string=string)
        if match:
            key_id = match.group("key_id")
            status = GPGStatus.NO_PUBKEY

        return GPGSignerStatus(
            fingerprint=fingerprint,
            key_id=key_id,
            status=status,
            timestamp=timestamp,
            trust=trust,
            username=username,
        )

    async def _exeute_command(self, *, args, stdin: bytes = None) -> GPGExecuteCommand:
        """Executes a gpg command and returns the response code, logging as needed."""
        kwargs = {"stdin": subprocess.PIPE} if stdin is not None else {}
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **kwargs,
        )
        stdout, stderr = await process.communicate(input=stdin)
        if process.returncode and self.log_gnupg_errors:
            LOGGER.debug(
                "Command Failed:\nArgs: %s\n---stdout---\n%s\n---stderr---\n%s",
                " ".join(args),
                stdout.decode("utf-8"),
                stderr.decode("utf-8"),
            )
        return GPGExecuteCommand(
            returncode=process.returncode, stderr=stderr, stdout=stdout
        )

    # Signer Members

    async def sign(self, *, data: bytes) -> str:
        if not self.keyid:
            raise RuntimeError("Cannot sign without keyid!")
        if not self.passphrase or len(self.passphrase) < 1:
            raise RuntimeError("Refusing to use an unprotected key!")

        # Write the data to a temporary file and invoke GnuPG to create a detached signature ...
        async with aiotempfile(mode="w+b") as datafile:
            signaturefile = Path(f"{datafile.name}.asc")

            # Write the data to a temporary file
            await datafile.write(data)
            await datafile.flush()

            # TODO: How can we "force" gpg2 to use the provided password, even when gpg-agent has the key loaded?
            args = [
                "gpg",
                "--armor",
                "--batch",
                "--default-key",
                str(self.keyid),
                "--detach-sign",
                "--digest-algo",
                "SHA512",
                "--homedir",
                str(self.homedir),
                "--no-emit-version",
                "--no-options",
                "--no-tty",
                "--passphrase-fd",
                "0",
                "--pinentry-mode",
                "loopback",
                "--sign",
                "--status-fd",
                "2",
                datafile.name,
            ]

            execute_command = await self._exeute_command(
                args=args, stdin=self.passphrase.encode("utf-8")
            )
            if execute_command.returncode:
                return ""

        # Retrieve the detached signature and cleanup ...
        try:
            async with aiofiles.open(signaturefile) as tmpfile:
                return await tmpfile.read()
        finally:
            signaturefile.unlink(missing_ok=True)

    async def verify(self, *, data: bytes, signature: str) -> Optional[GPGSignerVerify]:
        # Write the data and signature to temporary files and invoke GnuPG to verify they match ...
        async with aiotempfile(mode="w+b") as datafile:
            await datafile.write(data)
            await datafile.flush()
            async with aiotempfile(mode="w+b") as signaturefile:
                await signaturefile.write(signature.encode("utf-8"))
                await signaturefile.flush()

                args = [
                    "gpg",
                    "--batch",
                    "--homedir",
                    str(self.homedir),
                    "--no-emit-version",
                    "--no-options",
                    "--no-tty",
                    "--status-fd",
                    "2",
                    "--verify",
                    signaturefile.name,
                    datafile.name,
                ]

                execute_command = await self._exeute_command(args=args)
                status = await GPGSigner._parse_output(output=execute_command.stderr)

                # Assign metadata ...
                signer_long = signer_short = "Signature parsing failed!"
                try:
                    signer_short = f"keyid={status.key_id} status={status.status.value}"
                    signer_long = "\n".join(
                        [
                            f"{''.ljust(8)}Signature made {status.timestamp} using key ID {status.key_id}",
                            "".ljust(12) + status.username,
                        ]
                    )
                except:  # pylint: disable=bare-except
                    ...

                return GPGSignerVerify(
                    fingerprint=status.fingerprint,
                    key_id=status.key_id,
                    signer_long=signer_long,
                    signer_short=signer_short,
                    status=status.status.value,
                    timestamp=status.timestamp,
                    trust=status.trust.value,
                    type="gpg",
                    username=status.username,
                    valid=(status.status == GPGStatus.VALIDSIG)
                    and (status.trust in [GPGTrust.FULLY, GPGTrust.ULTIMATE]),
                )
