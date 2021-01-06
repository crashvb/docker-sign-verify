#!/usr/bin/env python

# pylint: disable=protected-access,redefined-builtin

"""Classes that provide asynchronous temporary file functionality."""

# ... while we wait for:
# * https://github.com/Tinche/aiofiles/issues/20
# * https://github.com/Tinche/aiofiles/pull/56/files

import asyncio
import logging
import os
import tempfile

from functools import partial
from pathlib import Path
from types import coroutine, MethodType

from aiofiles.base import AiofilesContextManager
from aiofiles.threadpool import sync_open, wrap

LOGGER = logging.getLogger(__name__)


def open(
    mode="w+b", suffix="", prefix=tempfile.template, dir="/tmp"
) -> AiofilesContextManager:
    """
    Create and return a temporary file.

    Args:
        mode: The mode argument to io.open (default "w+b").
        suffix: If 'suffix' is not None, the file name will end with that suffix, otherwise there will be no suffix.
        prefix:If 'prefix' is not None, the file name will begin with that prefix, otherwise a default prefix is used.
        dir: If 'dir' is not None, the file will be created in that directory, otherwise a default directory is used.

    Returns:
        The corresponding temporary file.
    """
    # pylint: disable=protected-access
    name = next(tempfile._RandomNameSequence())
    path = Path(dir).joinpath(f"{prefix}{name}{suffix}")

    # aiofiles_context_manager = aiofiles.open(path, mode=mode)
    aiofiles_context_manager = AiofilesContextManager(_open(path, mode=mode))
    aiofiles_context_manager.__setattr__("name", str(path))
    return aiofiles_context_manager


@coroutine
def _open(file, *args, mode="r", loop=None, executor=None, **kwargs):
    """Wrapping wrapped types that are instantiated in a concurrent generator makes my head hurt; punch the duck!"""
    if loop is None:
        loop = asyncio.get_event_loop()
    partial_function = partial(sync_open, file, *args, mode=mode, **kwargs)
    file_descriptior = yield from loop.run_in_executor(executor, partial_function)
    baseio = wrap(file_descriptior, loop=loop, executor=executor)

    # DUCK PUNCH: __del__()
    baseio.__del__ = MethodType(duck_punch___del__, baseio)

    # DUCK PUNCH: close()
    baseio._original_close = baseio.close
    baseio.close = MethodType(duck_punch_close, baseio)

    return baseio


def duck_punch___del__(self):
    """Ensure the file is deleted on __del__()."""
    try:
        os.unlink(self._file.name)
    except FileNotFoundError:
        ...


def duck_punch_close(self):
    """Ensure the file is delete on close()."""
    result = self._original_close()
    try:
        os.unlink(self._file.name)
    except FileNotFoundError:
        ...
    return result
