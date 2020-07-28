#!/usr/bin/env python

"""Docker sign command line interface."""

import logging
import os
import sys

from traceback import print_exception
from typing import TypedDict

import click

from click.core import Context
from docker_registry_client_async import ImageName
from docker_sign_verify import (
    ArchiveImageSource,
    DeviceMapperRepositoryImageSource,
    ImageSource,
    RegistryV2ImageSource,
    SignatureTypes,
)
from docker_sign_verify.imagesource import ImageSourceSignImage

from .common import (
    async_command,
    LOGGING_DEFAULT,
    logging_options,
    set_log_levels,
    version,
)
from .utils import to_image_name, HiddenPassword

LOGGER = logging.getLogger(__name__)


class TypingContextObject(TypedDict):
    # pylint: disable=missing-class-docstring
    dest_image_name: ImageName
    dry_run: bool
    imagesource: ImageSource
    keyid: str
    keypass: str
    signature_type: str
    sigtype: str
    src_image_name: ImageName
    verbosity: int


def get_context_object(context: Context) -> TypingContextObject:
    """Wrapper method to enforce type checking."""
    return context.obj


def sign_options(function):
    """Common signature creation options."""

    function = click.option(
        "-k",
        "--keyid",
        help="Signing key identifier.",
        required=True,
        envvar="DSV_KEYID",
    )(function)
    function = click.option(
        "-p",
        "--keypass",
        default=lambda: HiddenPassword(os.environ.get("DSV_KEYPASS", "")),
        help="Signing key passphrase.",
        hide_input=True,
        prompt=True,
    )(function)
    function = click.option(
        "-t",
        "--sigtype",
        default="gpg",
        envvar="DSV_KEYTYPE",
        help="Signature type.",
        show_default=True,
        type=click.Choice(["gpg", "pki"]),
    )(function)

    # Note: Order of argument is reversed, due to nesting ...
    # TODO: Should we support dissimilar src and dest image source types in the CLI?
    function = click.argument("dest_image_name", callback=to_image_name, required=True)(
        function
    )
    function = click.argument("src_image_name", callback=to_image_name, required=True)(
        function
    )
    return function


@async_command
async def sign(context: Context) -> ImageSourceSignImage:
    """Signs an image."""

    result = None

    ctx = get_context_object(context)
    try:
        if ctx["sigtype"] == "gpg" and ("." in ctx["keyid"] or "/" in ctx["keyid"]):
            LOGGER.warning("Key identifier looks like path, but signature type is GPG!")

        # TODO: Do we still need to use reflection here to avoid circular dependencies?
        module = __import__(__package__)
        sigtype = f"{ctx['sigtype'].upper()}Signer"
        if sigtype == "GPGSigner":
            signer_class = getattr(module, sigtype)
            signer = signer_class(keyid=ctx["keyid"], passphrase=ctx["keypass"])
        elif sigtype == "PKISigner":
            signer_class = getattr(module, sigtype)
            signer = signer_class(keypair_path=ctx["keyid"], passphrase=ctx["keypass"])
        else:
            raise RuntimeError(f"Unknown signature type: {ctx['sigtype']}!")

        result = await ctx["imagesource"].sign_image(
            signer,
            ctx["src_image_name"],
            ctx["imagesource"],
            ctx["dest_image_name"],
            SignatureTypes[ctx["signature_type"].upper()],
        )
        if ctx["dry_run"]:
            LOGGER.info(
                "Dry run completed for image: %s (%s)",
                ctx["dest_image_name"].resolve_name(),
                result["image_config"].get_digest(),
            )
        else:
            LOGGER.info(
                "Created new image: %s (%s)",
                ctx["dest_image_name"].resolve_name(),
                result["image_config"].get_digest(),
            )
    except Exception as exception:  # pylint: disable=broad-except
        if ctx["verbosity"] > 0:
            logging.fatal(exception)
        if ctx["verbosity"] > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx["imagesource"].close()

    return result


@click.group()
@click.option(
    "--dry-run", help="Do not write to destination image sources.", is_flag=True
)
@click.option(
    "-s",
    "--signature-type",
    help="(Co-)sign (default), endorse / countersign, or resign the source image",
    default="sign",
    type=click.Choice(["sign", "endorse", "resign"], case_sensitive=False),
)
@logging_options
@click.pass_context
def cli(
    context: Context,
    dry_run: False,
    signature_type: "sign",
    verbosity: int = LOGGING_DEFAULT,
):
    """Creates and embeds signatures into docker images."""

    if verbosity is None:
        verbosity = LOGGING_DEFAULT

    set_log_levels(verbosity)
    context.obj = {
        "dry_run": dry_run,
        "signature_type": signature_type,
        "verbosity": verbosity,
    }


@cli.command()
@click.option(
    "-a",
    "--archive",
    help="Uncompressed docker image archive.",
    required=True,
    type=click.Path(dir_okay=False, resolve_path=True),
)
@sign_options
@click.pass_context
# pylint: disable=redefined-outer-name,too-many-arguments
def archive(
    context: Context,
    keyid: str,
    keypass: str,
    sigtype: str,
    src_image_name: ImageName,
    dest_image_name: ImageName,
    archive: str,
):
    """Operates on docker-save produced archives."""

    ctx = get_context_object(context)
    ctx["keyid"] = keyid
    ctx["keypass"] = keypass
    ctx["sigtype"] = sigtype
    ctx["src_image_name"] = src_image_name
    ctx["dest_image_name"] = dest_image_name
    ctx["imagesource"] = ArchiveImageSource(archive=archive, dry_run=ctx["dry_run"])
    sign(context)


@cli.command()
@sign_options
@click.pass_context
# pylint: disable=too-many-arguments
def registry(
    context: Context,
    keyid: str,
    keypass: str,
    sigtype: str,
    src_image_name: ImageName,
    dest_image_name: ImageName,
):
    """Operates on docker registries (v2)."""

    ctx = get_context_object(context)
    ctx["keyid"] = keyid
    ctx["keypass"] = keypass
    ctx["sigtype"] = sigtype
    ctx["src_image_name"] = src_image_name
    ctx["dest_image_name"] = dest_image_name
    ctx["imagesource"] = RegistryV2ImageSource(dry_run=ctx["dry_run"])
    sign(context)


@cli.command()
@sign_options
@click.pass_context
# pylint: disable=too-many-arguments
def repository(
    context: Context,
    keyid: str,
    keypass: str,
    sigtype: str,
    src_image_name: ImageName,
    dest_image_name: ImageName,
):
    """Operates on docker repositories."""

    ctx = get_context_object(context)
    ctx["keyid"] = keyid
    ctx["keypass"] = keypass
    ctx["sigtype"] = sigtype
    ctx["src_image_name"] = src_image_name
    ctx["dest_image_name"] = dest_image_name
    ctx["imagesource"] = DeviceMapperRepositoryImageSource(dry_run=ctx["dry_run"])
    sign(context)


cli.add_command(version)

if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
