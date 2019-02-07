#!/usr/bin/env python

"""Docker sign command line interface."""

import logging
import os
import sys

import click
import urllib3

from docker_sign_verify import (
    __version__,
    ArchiveImageSource,
    DeviceMapperRepositoryImageSource,
    ImageName,
    RegistryV2ImageSource)

from .utils import (
    to_image_name,
    HiddenPassword
)

# Bug Fix: There isn't anything we can do about mis-configured remote certificates ...
urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)


def sign_options(function):
    """Common signature creation options."""
    function = click.option("-k", "--keyid", help="Signing key identifier.", required=True,
                            envvar="DSV_KEYID")(function)
    function = click.option("-p", "--keypass", default=lambda: HiddenPassword(os.environ.get("DSV_KEYPASS", "")),
                            help="Signing key passphrase.", hide_input=True, prompt=True)(function)
    function = click.option("-t", "--sigtype", default="gpg", envvar="DSV_KEYTYPE", help="Signature type.",
                            show_default=True, type=click.Choice(["gpg", "pki"]))(function)

    # Note: Order of argument is reversed, due to nesting ...
    # TODO: Should we support dissimilar src and dest image source types in the CLI?
    function = click.argument("dest_image_name", callback=to_image_name, required=True)(function)
    function = click.argument("src_image_name", callback=to_image_name, required=True)(function)
    return function


def sign(context):
    """Signs an image."""

    if context.obj["sigtype"] == "gpg" and ("." in context.obj["keyid"] or "/" in context.obj["keyid"]):
        logging.warning("Key identifier looks like path, but signature type is GPG!")

    signer_module = __import__("docker_sign_verify.signers")
    signer_class = getattr(signer_module, "{0}Signer".format(context.obj["sigtype"].upper()))
    signer = signer_class(context.obj["keyid"], context.obj["keypass"])

    context.obj["imagesource"].sign_image(signer, context.obj["src_image_name"], context.obj["imagesource"],
                                          context.obj["dest_image_name"])


@click.group()
@click.option("-s", "--silent", "verbosity", flag_value=0, help="Suppress all output.")
@click.option("-q", "--quiet", "verbosity", flag_value=1, help="Restrict output to warnings and errors.")
@click.option("-d", "--debug", "-v", "--verbose", "verbosity", flag_value=3, help="Show debug logging.")
@click.option("-vv", "--very-verbose", "verbosity", flag_value=4, help="Enable all logging.")
@click.pass_context
def cli(context, verbosity: int = 2):
    """Creates and embeds signatures into docker images."""

    levels = {
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
        4: logging.NOTSET
    }

    if verbosity is None:
        verbosity = 2

    if verbosity:
        logging.basicConfig(stream=sys.stdout, level=levels[verbosity])
    if verbosity < 3:
        logging.getLogger("gnupg").setLevel(logging.FATAL)
    if verbosity == 3:
        logging.getLogger("gnupg").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    context.obj = {}


@cli.command()
@click.option(
    "-a",
    "--archive",
    help="Uncompressed docker image archive.",
    required=True,
    type=click.Path(dir_okay=False, resolve_path=True))
@sign_options
@click.pass_context
# pylint: disable=redefined-outer-name
def archive(context, keyid: str, keypass: str, sigtype: str, src_image_name: ImageName, dest_image_name: ImageName,
            archive: str):
    """Operates on docker-save produced archives."""

    context.obj["keyid"] = keyid
    context.obj["keypass"] = keypass
    context.obj["sigtype"] = sigtype
    context.obj["src_image_name"] = src_image_name
    context.obj["dest_image_name"] = dest_image_name
    context.obj["imagesource"] = ArchiveImageSource(archive)
    sign(context)


@cli.command()
@sign_options
@click.pass_context
def registry(context, keyid: str, keypass: str, sigtype: str, src_image_name: ImageName, dest_image_name: ImageName):
    """Operates on docker registries (v2)."""

    context.obj["keyid"] = keyid
    context.obj["keypass"] = keypass
    context.obj["sigtype"] = sigtype
    context.obj["src_image_name"] = src_image_name
    context.obj["dest_image_name"] = dest_image_name
    context.obj["imagesource"] = RegistryV2ImageSource()
    sign(context)


@cli.command()
@sign_options
@click.pass_context
def repository(context, keyid: str, keypass: str, sigtype: str, src_image_name: ImageName, dest_image_name: ImageName):
    """Operates on docker repositories."""

    context.obj["keyid"] = keyid
    context.obj["keypass"] = keypass
    context.obj["sigtype"] = sigtype
    context.obj["src_image_name"] = src_image_name
    context.obj["dest_image_name"] = dest_image_name
    context.obj["imagesource"] = DeviceMapperRepositoryImageSource()
    sign(context)


@cli.command()
def version():
    """Displays the utility version."""

    print(__version__)


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
