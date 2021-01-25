#!/usr/bin/env python

"""Docker copy command line interface."""

import logging
import sys

from traceback import print_exception
from typing import cast, TypedDict

import click

from click.core import Context
from docker_registry_client_async import ImageName
from docker_sign_verify import (
    ArchiveImageSource,
    DeviceMapperRepositoryImageSource,
    ImageSource,
    RegistryV2ImageSource,
)

from .common import (
    async_command,
    LOGGING_DEFAULT,
    logging_options,
    set_log_levels,
    version,
)
from .docker_verify import (
    _verify,
    TypingContextObject as DockerVerifyTypingContextObject,
)
from .utils import to_image_name

LOGGER = logging.getLogger(__name__)


class TypingContextObject(TypedDict):
    # pylint: disable=missing-class-docstring
    check_signatures: bool
    dest_image_name: ImageName
    dry_run: bool
    imagesource: ImageSource
    src_image_name: ImageName
    verbosity: int


def get_context_object(context: Context) -> TypingContextObject:
    """Wrapper method to enforce type checking."""
    return context.obj


def copy_options(function):
    """Common copy options."""
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
async def copy(context: Context):
    """Copies and image."""

    ctx = get_context_object(context)
    try:
        ctx_verify = cast(DockerVerifyTypingContextObject, ctx)
        ctx_verify["images"] = [ctx["src_image_name"]]
        result = await _verify(ctx)
        result = result[0]

        await ctx["imagesource"].put_image(
            ctx["imagesource"],
            ctx["dest_image_name"],
            result["manifest"],
            result["image_config"],
            # TODO: Select compressed_layer_files vs uncompressed_layer_files based on type(imagesource).
            result["compressed_layer_files"],
        )
        if ctx["dry_run"]:
            LOGGER.info(
                "Dry run completed for image: %s (%s)",
                ctx["dest_image_name"].resolve_name(),
                result["image_config"].get_digest(),
            )
        else:
            LOGGER.info(
                "Replicated new image: %s (%s)",
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
    dry_run: False,
    verbosity: int = LOGGING_DEFAULT,
):
    """
    Replicates docker images while verifying embedded signatures, and the integrity of docker image layers and
    metadata.
    """

    if verbosity is None:
        verbosity = LOGGING_DEFAULT

    set_log_levels(verbosity)

    context.obj = {
        "check_signatures": check_signatures,
        "dry_run": dry_run,
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
@copy_options
@click.pass_context
# pylint: disable=redefined-outer-name
def archive(
    context: Context,
    src_image_name: ImageName,
    dest_image_name: ImageName,
    archive: str,
):
    """Operates on docker-save produced archives."""

    ctx = get_context_object(context)
    ctx["src_image_name"] = src_image_name
    ctx["dest_image_name"] = dest_image_name
    ctx["imagesource"] = ArchiveImageSource(archive=archive, dry_run=ctx["dry_run"])
    copy(context)


@cli.command()
@copy_options
@click.pass_context
def registry(context: Context, src_image_name: ImageName, dest_image_name: ImageName):
    """Operates on docker registries (v2)."""

    ctx = get_context_object(context)
    ctx["src_image_name"] = src_image_name
    ctx["dest_image_name"] = dest_image_name
    ctx["imagesource"] = RegistryV2ImageSource(dry_run=ctx["dry_run"])
    copy(context)


@cli.command()
@copy_options
@click.pass_context
def repository(context: Context, src_image_name: ImageName, dest_image_name: ImageName):
    """Operates on docker repositories."""

    ctx = get_context_object(context)
    ctx["src_image_name"] = src_image_name
    ctx["dest_image_name"] = dest_image_name
    ctx["imagesource"] = DeviceMapperRepositoryImageSource(dry_run=ctx["dry_run"])
    copy(context)


cli.add_command(version)

if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
