#!/usr/bin/env python

# pylint: disable=too-many-arguments

"""Stub classes for offline testing."""

import shlex
import sys

from typing import Any, Dict, NamedTuple, Optional

from click.testing import CliRunner, Result
from docker_sign_verify import Signer


class DSVCliRunner(CliRunner):
    """
    click.testing.CliRunner.invoke w/o isolation, as it breaks logging:
    https://github.com/pallets/click/issues/824
    """

    def invoke(self, cli, args=None, catch_exceptions=True, **extra) -> Result:
        # pylint: disable=arguments-differ
        exc_info = None
        exception = None
        exit_code = 0

        if isinstance(args, str):
            args = shlex.split(args)

        if "prog_name" not in extra:
            extra["prog_name"] = self.get_default_prog_name(cli)

        try:
            cli.main(args=args or (), **extra)
        except SystemExit as exc:
            exc_info = sys.exc_info()
            exit_code = exc.code
            if exit_code is None:
                exit_code = 0

            if exit_code != 0:
                exception = exc

            if not isinstance(exit_code, int):
                sys.stdout.write(str(exit_code))
                sys.stdout.write("\n")
                exit_code = 1

        except Exception as exc:  # pylint: disable=broad-except
            if not catch_exceptions:
                raise
            exc_info = sys.exc_info()
            exit_code = 1
            exception = exc

        return Result(
            exception=exception,
            exit_code=exit_code,
            exc_info=exc_info,
            return_value=exit_code,
            runner=self,
            stderr_bytes=b"",
            stdout_bytes=b"",
        )


def _signer_for_signature(
    signature: str, *, signer_kwargs: Dict[str, Dict] = None
) -> Signer:
    """Override of docker_sign_verify.Signer::_for_signature()."""
    if signer_kwargs is None:
        signer_kwargs = {}

    if "FAKE SIGNATURE" in signature:
        kwargs = signer_kwargs.get("FakeSigner", {})
        return FakeSigner(**kwargs)
    raise RuntimeError("Unsupported signature type!")


class FakeSignerVerify(NamedTuple):
    # pylint: disable=missing-class-docstring
    assignable_value: Optional[Any]
    signer_long: Optional[str]
    signer_short: Optional[str]
    type: str
    valid: bool


class FakeSigner(Signer):
    """Creates and verifies docker image signatures static strings."""

    DEFAULT_ASSIGNABLE_VALUE = "DEFAULT_ASSIGNABLE_VALUE"

    def __init__(
        self,
        signature_value: str = "-----BEGIN FAKE SIGNATURE-----\nDEFAULT FAKE SIGNATURE\n-----END FAKE SIGNATURE-----",
        *,
        assignable_value: str = DEFAULT_ASSIGNABLE_VALUE,
    ):
        self.assignable_value = assignable_value
        self.signature_value = signature_value

    def _get_signature(self, *, data: bytes) -> str:
        return self.signature_value.format(data)

    # Signer Members

    async def sign(self, *, data: bytes) -> str:
        return self._get_signature(data=data)

    async def verify(self, *, data: bytes, signature: str) -> FakeSignerVerify:
        valid = signature == self._get_signature(data=data)
        result = FakeSignerVerify(
            assignable_value=self.assignable_value,
            signer_long=f"{''.ljust(8)}This is a fake signature for testing.",
            signer_short="f-a-k-e",
            type="fake",
            valid=valid,
        )

        # Assign metadata ...
        # TODO: Add better debug logging

        return result
