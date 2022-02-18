#!/usr/bin/env python

"""Utility classes."""

import logging
import sys

from functools import wraps
from logging import Formatter

import asyncio
import click

from docker_registry_client_async import ImageName

LOGGING_DEFAULT = 2


class CustomFormatter(Formatter):
    # pylint: disable=too-few-public-methods
    """Allows for ANSI coloring of logs."""
    COLORS = {
        logging.DEBUG: "[38;20m",
        logging.INFO: "[34;20m",
        logging.WARNING: "[33;20m",
        logging.ERROR: "[31;20m",
        logging.CRITICAL: "[31;1m",
    }

    def format(self, record):
        return f"\x1b{CustomFormatter.COLORS[record.levelno]}{super().format(record=record)}\x1b[0m"


class HiddenPassword:
    # pylint: disable=too-few-public-methods
    """Helper class to mask password input."""

    def __init__(self, password: str = ""):
        """
        Args:
            password: The password.
        """
        self.password = password

    def __len__(self):
        return len(self.password)

    def __str__(self):
        return "*" * len(self.password)


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
    # pylint: disable=protected-access
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
        logging.getLogger("pretty_bad_protocol").setLevel(logging.FATAL)
    # debug / verbose ...
    elif verbosity == LOGGING_DEFAULT + 1:
        _format = "%(asctime)s %(levelname)-8s %(message)s"
        logging.getLogger("pretty_bad_protocol").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    # very verbose ...
    else:
        # _format = "%(asctime)s.%(msecs)d %(levelname)-8s %(name)s %(message)s"
        _format = "%(asctime)s.%(msecs)d %(levelname)-8s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"

    logging.basicConfig(
        datefmt="%Y-%m-%d %H:%M:%S",
        format=_format,
        level=levels[verbosity],
        stream=sys.stdout,
    )

    # No need to loop over handlers or perform None checks as we know from basicConfig() there is only one, and it has
    # a formatter assigned.
    handler = logging.getLogger().handlers[0]
    handler.formatter = CustomFormatter(fmt=handler.formatter._fmt)


def to_image_name(context, param, value: str) -> ImageName:
    # pylint: disable=unused-argument
    """Converts an docker image name to an ImageName."""
    if isinstance(value, str):
        result = ImageName.parse(value)
    else:
        result = [ImageName.parse(v) for v in value]
    return result
