#!/usr/bin/env python

"""Docker verify command line interface."""

from typing import List

import click
import urllib3

from docker_sign_verify import (
    ArchiveImageSource,
    DeviceMapperRepositoryImageSource,
    RegistryV2ImageSource,
)

from .common import logging_options, set_log_levels, version
from .utils import to_image_name


# Bug Fix: There isn't anything we can do about mis-configured remote certificates ...
urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)


def verify_options(function):
    """Common verification options."""
    function = click.argument(
        "images", callback=to_image_name, nargs=-1, required=True
    )(function)
    return function


def verify(context):
    """Verifies an image(s)."""
    for image_name in context.obj["images"]:
        if context.obj["check_signatures"]:
            context.obj["imagesource"].verify_image_signatures(image_name)
        else:
            context.obj["imagesource"].verify_image_integrity(image_name)


@click.group()
@click.option(
    "--check-signatures/--no-check-signatures",
    default=True,
    help="Toggles integrity vs integrity and signature checking.",
    show_default=True,
)
@logging_options
@click.pass_context
def cli(context, check_signatures: bool, verbosity: int = 2):
    """Verifies embedded signatures, and the integrity of docker image layers and metadata."""

    set_log_levels(verbosity)

    context.obj = {"check_signatures": check_signatures}


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
def archive(context, images: List, archive: str):
    """Operates on docker-save produced archives."""

    context.obj["images"] = images
    context.obj["imagesource"] = ArchiveImageSource(archive=archive)
    verify(context)


@cli.command()
@verify_options
@click.pass_context
def registry(context, images: List):
    """Operates on docker registries (v2)."""

    context.obj["images"] = images
    context.obj["imagesource"] = RegistryV2ImageSource()
    verify(context)


@cli.command()
@verify_options
@click.pass_context
def repository(context, images: List):
    """Operates on docker repositories."""

    context.obj["images"] = images
    context.obj["imagesource"] = DeviceMapperRepositoryImageSource()
    verify(context)


cli.add_command(version)

if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
