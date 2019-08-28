#!/usr/bin/env python

"""Docker copy command line interface."""

import logging

import click
import urllib3

from docker_sign_verify import (
    ArchiveImageSource,
    DeviceMapperRepositoryImageSource,
    ImageName,
    RegistryV2ImageSource,
)

from .common import logging_options, set_log_levels, version
from .docker_verify import verify
from .utils import to_image_name

LOGGER = logging.getLogger(__name__)

# Bug Fix: There isn't anything we can do about mis-configured remote certificates ...
urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)


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


def copy(context):
    """Copies and image."""
    context.obj["images"] = [context.obj["src_image_name"]]
    result = verify(context)[0]

    context.obj["imagesource"].put_image(
        context.obj["imagesource"],
        context.obj["dest_image_name"],
        result["manifest"],
        result["image_config"],
        # TODO: Select compressed_layer_files vs uncompressed_layer_files based on type(imagesource).
        result["compressed_layer_files"],
    )
    if context.obj["dry_run"]:
        LOGGER.info(
            "Dry run completed for image: %s (%s)",
            context.obj["dest_image_name"].resolve_name(),
            result["image_config"].get_config_digest(),
        )
    else:
        LOGGER.info(
            "Created new image: %s (%s)",
            context.obj["dest_image_name"].resolve_name(),
            result["image_config"].get_config_digest(),
        )


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
def cli(context, check_signatures: bool, dry_run: False, verbosity: int = 2):
    """
    Replicates docker images while verifying embedded signatures, and the integrity of docker image layers and metadata.
    """

    set_log_levels(verbosity)

    context.obj = {"check_signatures": check_signatures, "dry_run": dry_run}


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
    context, src_image_name: ImageName, dest_image_name: ImageName, archive: str
):
    """Operates on docker-save produced archives."""

    context.obj["src_image_name"] = src_image_name
    context.obj["dest_image_name"] = dest_image_name
    context.obj["imagesource"] = ArchiveImageSource(
        archive=archive, dry_run=context.obj["dry_run"]
    )
    copy(context)


@cli.command()
@copy_options
@click.pass_context
def registry(context, src_image_name: ImageName, dest_image_name: ImageName):
    """Operates on docker registries (v2)."""

    context.obj["src_image_name"] = src_image_name
    context.obj["dest_image_name"] = dest_image_name
    context.obj["imagesource"] = RegistryV2ImageSource(dry_run=context.obj["dry_run"])
    copy(context)


@cli.command()
@copy_options
@click.pass_context
def repository(context, src_image_name: ImageName, dest_image_name: ImageName):
    """Operates on docker repositories."""

    context.obj["src_image_name"] = src_image_name
    context.obj["dest_image_name"] = dest_image_name
    context.obj["imagesource"] = DeviceMapperRepositoryImageSource(
        dry_run=context.obj["dry_run"]
    )
    copy(context)


cli.add_command(version)

if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
