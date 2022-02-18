#!/usr/bin/env python

"""Utility classes."""

import gzip
import hashlib
import logging
import os

from pathlib import Path
from typing import NamedTuple

from docker_registry_client_async import FormattedSHA256
from docker_registry_client_async.utils import (
    async_wrap,
    be_kind_rewind,
    CHUNK_SIZE as DRCA_CHUNK_SIZE,
)

LOGGER = logging.getLogger(__name__)

CHUNK_SIZE = int(os.environ.get("DSV_CHUNK_SIZE", DRCA_CHUNK_SIZE))


class UtilChunkFile(NamedTuple):
    # pylint: disable=missing-class-docstring
    digest: FormattedSHA256
    size: int


async def chunk_file(
    file_in, file_out, *, file_in_is_async: bool = True, file_out_is_async: bool = True
) -> UtilChunkFile:
    """
    Copies chunkcs from one file to another.

    Args:
        file_in: The file from which to retrieve the file chunks.
        file_out: The file to which to store the file chunks.
        file_in_is_async: If True, all file_in IO operations will be awaited.
        file_out_is_async: If True, all file_out IO operations will be awaited.

    Returns:
        NamedTuple:
            digest: The digest value of the chunked data.
            size: The byte size of the chunked data in bytes.
    """
    coroutine_read = file_in.read if file_in_is_async else async_wrap(file_in.read)
    coroutine_write = (
        file_out.write if file_out_is_async else async_wrap(file_out.write)
    )
    hasher = hashlib.sha256()
    size = 0
    while True:
        chunk = await coroutine_read(CHUNK_SIZE)
        if not chunk:
            break
        await coroutine_write(chunk)
        hasher.update(chunk)
        size += len(chunk)

    await be_kind_rewind(file_out, file_is_async=file_out_is_async)

    return UtilChunkFile(digest=FormattedSHA256(hasher.hexdigest()), size=size)


def xellipsis(string: str) -> str:
    """
    Reduces the length of a given string, if it is wider than the terminal width, inserting str_ellipsis.

    Args:
        string: The string to be reduced.

    Returns:
        A string with a maximum length of the terminal width.
    """
    return str_ellipsis(string, os.environ.get("COLUMNS", 80) / 2)


def str_ellipsis(string: str, max_length: int = 40) -> str:
    """
    Reduces the length of a given string, if it is over a certain length, by inserting str_ellipsis.

    Args:
        string: The string to be reduced.
        max_length: The maximum length of the string.

    Returns:
        A string with a maximum length of :param:max_length.
    """
    if len(string) <= max_length:
        return string
    n_2 = int(max_length) / 2 - 3
    n_1 = max_length - n_2 - 3

    return f"{string[:int(n_1)]}...{string[-int(n_2):]}"


async def gunzip(path: Path, file_out, file_out_is_async: bool = True) -> UtilChunkFile:
    """
    Uncompresses a given gzip archive.

    Args:
        path: Path to the gzipped file.
        file_out: The output file.
        file_out_is_async: If True, all file_out IO operations will be awaited.

    Returns:
        NamedTuple: as defined by :func:~docker_sign_verify.Utils._chunk_file.
    """
    # TODO: Implement an async GzipFile ...
    with gzip.GzipFile(filename=path, mode="rb") as file_in:
        return await chunk_file(
            file_in,
            file_out,
            file_in_is_async=False,
            file_out_is_async=file_out_is_async,
        )
