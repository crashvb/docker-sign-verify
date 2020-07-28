#!/usr/bin/env python

"""Common CLI commands."""

import logging
import sys

from functools import wraps

import asyncio
import click

from docker_sign_verify import __version__

LOGGING_DEFAULT = 2


def async_command(func):
    """Asynchronous command wrapper that allows click commands to be async."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        # pylint: disable=no-member,protected-access
        coroutine = func(*args, **kwargs)
        event_loop = asyncio._get_running_loop()
        # Allow func to be called, or awaited ...
        if event_loop is None:
            return asyncio.run(coroutine)
        return coroutine

    return wrapper


def logging_options(function):
    """Common logging options."""

    function = click.option(
        "-s",
        "--silent",
        "verbosity",
        flag_value=LOGGING_DEFAULT - 2,
        help="Suppress all output.",
    )(function)
    function = click.option(
        "-q",
        "--quiet",
        "verbosity",
        flag_value=LOGGING_DEFAULT - 1,
        help="Restrict output to warnings and errors.",
    )(function)
    function = click.option(
        "-d",
        "--debug",
        "-v",
        "--verbose",
        "verbosity",
        flag_value=LOGGING_DEFAULT + 1,
        help="Show debug logging.",
    )(function)
    function = click.option(
        "-vv",
        "--very-verbose",
        "verbosity",
        flag_value=LOGGING_DEFAULT + 2,
        help="Enable all logging.",
    )(function)

    return function


def set_log_levels(verbosity: int = LOGGING_DEFAULT):
    """
    Assigns the logging levels in a consistent way.

    Args:
        verbosity: The logging verbosity level from  0 (least verbose) to 4 (most verbose).
    """
    levels = {
        0: logging.FATAL + 10,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
        4: logging.NOTSET,
    }

    _format = None
    # normal, quiet, silent ...
    if verbosity <= LOGGING_DEFAULT:
        _format = "%(message)s"
        logging.getLogger("gnupg").setLevel(logging.FATAL)
    # debug / verbose ...
    elif verbosity == LOGGING_DEFAULT + 1:
        _format = "%(asctime)s %(levelname)-8s %(message)s"
        logging.getLogger("gnupg").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    # very verbose ...
    else:
        # _format = "%(asctime)s.%(msecs)d %(levelname)-8s %(name)s %(message)s"
        _format = "%(asctime)s.%(msecs)d %(levelname)-8s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"

    logging.basicConfig(
        stream=sys.stdout,
        level=levels[verbosity],
        format=_format,
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@click.command()
def version():
    """Displays the utility version."""
    print(__version__)
