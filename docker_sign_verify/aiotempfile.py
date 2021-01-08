#!/usr/bin/env python

# pylint: disable=protected-access,redefined-builtin

"""Classes that provide asynchronous temporary file functionality."""

# ... while we wait for:
# * https://github.com/Tinche/aiofiles/issues/20
# * https://github.com/Tinche/aiofiles/pull/56/files

import asyncio
import atexit
import os
import tempfile
import sys

from functools import partial
from pathlib import Path
from traceback import print_exception
from types import coroutine, MethodType

from aiofiles.base import AiofilesContextManager
from aiofiles.threadpool import sync_open, wrap

_OBJECTS = []


@atexit.register
def deterministic_destructor():
    """
    Duck punching the python garbage collector.

    This is needed to cleanup files that are created by awaiting the context manager.
    """
    global _OBJECTS  # pylint: disable=global-statement
    # Copy the list to allow modification while iterating
    for obj in _OBJECTS[:]:
        try:
            obj.close()
        except Exception:  # pylint: disable=broad-except
            exc_info = sys.exc_info()
            print_exception(*exc_info)


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
    name = next(tempfile._RandomNameSequence())  # pylint: disable=protected-access
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
    file_descriptor = yield from loop.run_in_executor(executor, partial_function)
    obj = wrap(file_descriptor, loop=loop, executor=executor)

    # DUCK PUNCH: __del__()
    obj._original___del__ = getattr(obj, "__del__", None)
    obj.__del__ = MethodType(duck_punch___del__, obj)

    # DUCK PUNCH: close()
    obj._original_close = getattr(obj, "close", None)
    obj.close = MethodType(duck_punch_close, obj)

    global _OBJECTS  # pylint: disable=global-statement
    _OBJECTS.append(obj)
    return obj


def duck_punch___del__(self):
    """Ensure the file is deleted on __del__()."""
    global _OBJECTS  # pylint: disable=global-statement
    if self._original___del__:
        self._original___del__()
    try:
        os.unlink(self._file.name)
    except FileNotFoundError:
        ...
    finally:
        try:
            _OBJECTS.remove(self)
        except ValueError:
            ...


def duck_punch_close(self):
    """Ensure the file is delete on close()."""
    global _OBJECTS  # pylint: disable=global-statement
    result = None
    if self._original_close:
        result = self._original_close()
    try:
        os.unlink(self._file.name)
    except FileNotFoundError:
        ...
    finally:
        try:
            _OBJECTS.remove(self)
        except ValueError:
            ...
    return result
