#!/usr/bin/env python

# pylint: disable=too-many-arguments

"""docker-sign-verify command line interface."""

import logging
import os
import sys

from traceback import print_exception
from typing import List, NamedTuple

import click

from click.core import Context
from docker_registry_client_async import ImageName
from docker_sign_verify import (
    __version__,
    RegistryV2,
    RegistryV2SignImage,
    RegistryV2VerifyImageSignatures,
    SignatureTypes,
)

from .utils import (
    async_command,
    LOGGING_DEFAULT,
    logging_options,
    set_log_levels,
    to_image_name,
    HiddenPassword,
)

LOGGER = logging.getLogger(__name__)


class TypingContextObject(NamedTuple):
    # pylint: disable=missing-class-docstring
    check_signatures: bool
    registryv2: RegistryV2
    verbosity: int


def get_context_object(*, context: Context) -> TypingContextObject:
    """Wrapper method to enforce type checking."""
    return context.obj


async def _verify(
    *, ctx: TypingContextObject, images: List[ImageName]
) -> List[RegistryV2VerifyImageSignatures]:
    """Verifies an image(s)."""

    results = []

    for image_name in images:
        if ctx.check_signatures:
            result = await ctx.registryv2.verify_image_signatures(image_name=image_name)
            LOGGER.info(
                "Image %s (%s) is consistent; %d signature(s) verified.",
                image_name.resolve_name(),
                result.image_config.get_digest(),
                len(result.signatures.signatures),
            )
        else:
            result = await ctx.registryv2.verify_image_integrity(image_name=image_name)
            LOGGER.info(
                "Image %s (%s) is consistent.",
                image_name.resolve_name(),
                result.image_config.get_digest(),
            )
            LOGGER.info("Image signature(s) NOT verified.")
        results.append(result)

    return results


@click.group()
@click.option(
    "--check-signatures/--no-check-signatures",
    default=True,
    help="Toggles integrity vs integrity and signature checking.",
    show_default=True,
)
@click.option(
    "--dry-run", help="Do not write to destination image sources.", is_flag=True
)
@logging_options
@click.pass_context
def cli(
    context: Context,
    check_signatures: bool,
    dry_run: bool,
    verbosity: int = LOGGING_DEFAULT,
):
    """Utility for signing and verifying docker images."""

    if verbosity is None:
        verbosity = LOGGING_DEFAULT

    set_log_levels(verbosity)
    context.obj = TypingContextObject(
        check_signatures=check_signatures,
        registryv2=RegistryV2(dry_run=dry_run),
        verbosity=verbosity,
    )


@cli.command()
@click.argument("image_name_src", callback=to_image_name, required=True)
@click.argument("image_name_dest", callback=to_image_name, required=True)
@click.pass_context
@async_command
async def copy(context: Context, image_name_dest: ImageName, image_name_src: ImageName):
    """Copies and image."""

    result = None
    ctx = get_context_object(context=context)
    try:
        result = await _verify(ctx=ctx, images=[image_name_src])
        result = result[0]

        await ctx.registryv2.put_image(
            image_config=result.image_config,
            image_name=image_name_dest,
            # TODO: Select compressed_layer_files vs uncompressed_layer_files based on type(registryv2).
            layer_files=result.compressed_layer_files,
            manifest=result.manifest,
            manifest_list=result.manifest_list,
        )
        if ctx.registryv2.dry_run:
            LOGGER.info(
                "Dry run completed for image: %s (%s)",
                image_name_dest.resolve_name(),
                result.image_config.get_digest(),
            )
        else:
            LOGGER.info(
                "Replicated new image: %s (%s)",
                image_name_dest.resolve_name(),
                result.image_config.get_digest(),
            )
    except Exception as exception:  # pylint: disable=broad-except
        if ctx.verbosity > 0:
            logging.fatal(exception)
        if ctx.verbosity > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx.registryv2.close()
        if result:
            result.close()


@cli.command()
@click.argument("image_name_src", callback=to_image_name, required=True)
@click.argument("image_name_dest", callback=to_image_name, required=True)
@click.option(
    "-s",
    "--signature-type",
    help="(Co-)sign (default), endorse / countersign, or resign the source image",
    default="sign",
    type=click.Choice(["sign", "endorse", "resign"], case_sensitive=False),
)
@click.option(
    "-k",
    "--keyid",
    help="Signing key identifier.",
    required=True,
    envvar="DSV_KEYID",
)
@click.option(
    "-p",
    "--keypass",
    default=lambda: HiddenPassword(os.environ.get("DSV_KEYPASS", "")),
    help="Signing key passphrase.",
    hide_input=True,
    prompt=True,
)
@click.option(
    "-t",
    "--sigtype",
    default="gpg",
    envvar="DSV_KEYTYPE",
    help="Signature type.",
    show_default=True,
    type=click.Choice(["gpg", "pki"]),
)
@click.pass_context
@async_command
async def sign(
    context: Context,
    image_name_dest: ImageName,
    image_name_src: ImageName,
    keyid: str,
    keypass: str,
    signature_type: str,
    sigtype: str,
) -> RegistryV2SignImage:
    """Signs an image."""

    result = None
    ctx = get_context_object(context=context)
    try:
        if sigtype == "gpg" and ("." in keyid or "/" in keyid):
            LOGGER.warning("Key identifier looks like path, but signature type is GPG!")

        # TODO: Do we still need to use reflection here to avoid circular dependencies?
        module = __import__(__package__)
        sigtype = f"{sigtype.upper()}Signer"
        if sigtype == "GPGSigner":
            signer_class = getattr(module, sigtype)
            signer = signer_class(keyid=keyid, passphrase=keypass)
        elif sigtype == "PKISigner":
            signer_class = getattr(module, sigtype)
            signer = signer_class(keypair_path=keyid, passphrase=keypass)
        else:
            raise RuntimeError(f"Unknown signature type: {sigtype}!")

        result = await ctx.registryv2.sign_image(
            image_name_dest=image_name_dest,
            image_name_src=image_name_src,
            signature_type=SignatureTypes[signature_type.upper()],
            signer=signer,
        )
        result.verify_image_data.close()
        if ctx.registryv2.dry_run:
            LOGGER.info(
                "Dry run completed for image: %s (%s)",
                image_name_dest.resolve_name(),
                result.image_config.get_digest(),
            )
        else:
            LOGGER.info(
                "Created new image: %s (%s)",
                image_name_dest.resolve_name(),
                result.image_config.get_digest(),
            )
    except Exception as exception:  # pylint: disable=broad-except
        if ctx.verbosity > 0:
            logging.fatal(exception)
        if ctx.verbosity > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx.registryv2.close()
        if result:
            result.verify_image_data.close()

    return result


@cli.command()
@click.argument("images", callback=to_image_name, nargs=-1, required=True)
@click.pass_context
@async_command
async def verify(
    context: Context,
    images: List[ImageName],
) -> List[RegistryV2VerifyImageSignatures]:
    """Verifies an image(s)."""

    results = []
    ctx = get_context_object(context=context)
    try:
        results = await _verify(ctx=ctx, images=images)
    except Exception as exception:  # pylint: disable=broad-except
        if ctx.verbosity > 0:
            logging.fatal(exception)
        if ctx.verbosity > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx.registryv2.close()
        for result in results:
            result.close()

    return results


@click.command()
def version():
    """Displays the utility version."""
    print(__version__)


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
