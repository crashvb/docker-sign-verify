#!/usr/bin/env python

"""Docker verify command line interface."""

import logging
import sys

from traceback import print_exception
from typing import List, TypedDict

import click

from click.core import Context
from docker_registry_client_async import ImageName
from docker_sign_verify import (
    ArchiveImageSource,
    DeviceMapperRepositoryImageSource,
    ImageSource,
    RegistryV2ImageSource,
)
from docker_sign_verify.imagesource import ImageSourceVerifyImageSignatures

from .common import (
    async_command,
    LOGGING_DEFAULT,
    logging_options,
    set_log_levels,
    version,
)
from .utils import to_image_name

LOGGER = logging.getLogger(__name__)


class TypingContextObject(TypedDict):
    # pylint: disable=missing-class-docstring
    check_signatures: bool
    images: List[ImageName]
    imagesource: ImageSource
    verbosity: int


def get_context_object(context: Context) -> TypingContextObject:
    """Wrapper method to enforce type checking."""
    return context.obj


def verify_options(function):
    """Common verification options."""

    function = click.argument(
        "images", callback=to_image_name, nargs=-1, required=True
    )(function)
    return function


async def _verify(ctx: TypingContextObject) -> List[ImageSourceVerifyImageSignatures]:
    """Verifies an image(s)."""

    results = []

    for image_name in ctx["images"]:
        if ctx["check_signatures"]:
            result = await ctx["imagesource"].verify_image_signatures(image_name)
            LOGGER.info(
                "Image %s (%s) is consistent; %d signature(s) verified.",
                image_name.resolve_name(),
                result["image_config"].get_digest(),
                len(result["signatures"]["signatures"]),
            )
        else:
            result = await ctx["imagesource"].verify_image_integrity(image_name)
            LOGGER.info(
                "Image %s (%s) is consistent.",
                image_name.resolve_name(),
                result["image_config"].get_digest(),
            )
            LOGGER.info("Image signature(s) NOT verified.")
        results.append(result)

    return results


@async_command
async def verify(context: Context) -> List[ImageSourceVerifyImageSignatures]:
    """Verifies an image(s)."""

    results = []

    ctx = get_context_object(context)
    try:
        results = await _verify(ctx)
    except Exception as exception:  # pylint: disable=broad-except
        if ctx["verbosity"] > 0:
            logging.fatal(exception)
        if ctx["verbosity"] > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx["imagesource"].close()

    return results


@click.group()
@click.option(
    "--check-signatures/--no-check-signatures",
    default=True,
    help="Toggles integrity vs integrity and signature checking.",
    show_default=True,
)
@logging_options
@click.pass_context
def cli(context: Context, check_signatures: bool, verbosity: int = LOGGING_DEFAULT):
    """Verifies embedded signatures, and the integrity of docker image layers and metadata."""

    if verbosity is None:
        verbosity = LOGGING_DEFAULT

    set_log_levels(verbosity)
    context.obj = {"check_signatures": check_signatures, "verbosity": verbosity}


@cli.command()
@click.option(
    "-a",
    "--archive",
    help="Uncompressed docker image archive.",
    required=True,
    type=click.Path(dir_okay=False, resolve_path=True),
)
@verify_options
@click.pass_context
# pylint: disable=redefined-outer-name
def archive(context: Context, images: List[ImageName], archive: str):
    """Operates on docker-save produced archives."""

    ctx = get_context_object(context)
    ctx["images"] = images
    ctx["imagesource"] = ArchiveImageSource(archive=archive)
    verify(context)


@cli.command()
@verify_options
@click.pass_context
def registry(context: Context, images: List[ImageName]):
    """Operates on docker registries (v2)."""

    ctx = get_context_object(context)
    ctx["images"] = images
    ctx["imagesource"] = RegistryV2ImageSource()
    verify(context)


@cli.command()
@verify_options
@click.pass_context
def repository(context: Context, images: List[ImageName]):
    """Operates on docker repositories."""

    ctx = get_context_object(context)
    ctx["images"] = images
    ctx["imagesource"] = DeviceMapperRepositoryImageSource()
    verify(context)


cli.add_command(version)

if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
