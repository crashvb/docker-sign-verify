#!/usr/bin/env python

"""Utility classes."""

import gzip
import hashlib
import io
import logging
import os
import shutil
import tarfile
import tempfile
import time

from pathlib import Path
from typing import TypedDict

import aiofiles

from docker_registry_client_async import FormattedSHA256
from docker_registry_client_async.hashinggenerator import HashingGenerator
from docker_registry_client_async.utils import (
    async_wrap,
    be_kind_rewind,
    CHUNK_SIZE as DRCA_CHUNK_SIZE,
)

LOGGER = logging.getLogger(__name__)

CHUNK_SIZE = int(os.environ.get("DSV_CHUNK_SIZE", DRCA_CHUNK_SIZE))


class UtilChunkFile(TypedDict):
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
        dict:
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

    return {"digest": FormattedSHA256(hasher.hexdigest()), "size": size}


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

    return "{0}...{1}".format(string[: int(n_1)], string[-int(n_2) :])


async def read_file(path: Path) -> bytes:
    """
    Generator that asynchronously reads from a given file.

    Args:
        path: Absolute path of the file to be read.

    Returns:
        The file content.
    """
    async with aiofiles.open(path, mode="r+b") as file:
        return bytes(HashingGenerator(file))


async def write_file(path: Path, content: bytes):
    """
    Assigns the entire contents of a file.

    Args:
        path: Absolute path of the file to be assigned.
        content: The content to be assigned.
    """
    async with aiofiles.open(path, mode="w+b") as file:
        # TODO: Split content into chunks ...
        # TODO: Should we digest here?
        await file.write(content)


# TODO: Convert to aysnc
def tar_mkdir(file_out, name: str):
    """
    Creates an empty directory in a given tar archive on disk.

    Args:
        file_out: The output file.
        name: Name of the directory to be created.
    """
    with tarfile.TarFile("tar-archive", "a", file_out) as tfile_out:
        tarinfo = tfile_out.tarinfo()
        tarinfo.mode = 0o0755
        tarinfo.mtime = time.time()
        tarinfo.name = name
        tarinfo.tarfile = tfile_out
        tarinfo.type = tarfile.DIRTYPE
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = ""
        tfile_out.addfile(tarinfo)


# TODO: What is the type of "content"?
def tar_add_file(file_out, name: str, content):
    """
    Creates a file from memory in a given tar archive on disk.

    Args:
        file_out: The output file.
        name: The name of the file to be created
        content: The corresponding file content.
    """
    bytesio = io.BytesIO(content)
    bytesio.seek(0)
    with tarfile.TarFile("tar-archive", "a", file_out) as tfile_out:
        tarinfo = tfile_out.tarinfo()
        tarinfo.mode = 0o0644
        tarinfo.mtime = time.time()
        tarinfo.name = name
        tarinfo.tarfile = tfile_out
        tarinfo.size = len(content)
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = ""
        tfile_out.addfile(tarinfo, bytesio)


def tar_add_file_from_disk(file_out, name: str, file_in):
    """
    Adds a file to a given tar archive on disk to disk.

    Args:
        file_out: The output file (tar).
        name: The name of the file to be added.
        file_in: The input file.
    """
    with tarfile.TarFile("tar-archive", "a", file_out) as tfile_out:
        tarinfo = tfile_out.gettarinfo(None, name, file_in)
        tarinfo.mode = 0o0644
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = ""
        tfile_out.addfile(tarinfo, file_in)


# TODO: Convert to aysnc
def tar_delete_file(file_out, name: str):
    """
    Removes a file from a given tar archive on disk.

    Args:
        file_out: The output file.
        name: The name of the file to be removed.
    """
    with tempfile.TemporaryFile() as tmp:
        with tarfile.open(fileobj=file_out) as tfile_in:
            with tarfile.open(fileobj=tmp, mode="w") as tfile_out:
                for tarinfo in tfile_in:
                    if tarinfo.name == name:
                        continue

                    if tarinfo.type == tarfile.DIRTYPE:
                        tfile_out.addfile(tarinfo)
                    else:
                        handle = tfile_in.extractfile(tarinfo)
                        tfile_out.addfile(tarinfo, handle)
        file_out.seek(0)
        tmp.seek(0)
        shutil.copyfileobj(tmp, file_out)


async def untar(
    file_in, name: str, file_out, *, file_out_is_async: bool = True
) -> UtilChunkFile:
    """
    Extracts a file from a given tar archive.

    Args:
        file_in: The input file (tar).
        name: The name of the file to be extracted.
        file_out: The output file.
        file_out_is_async: If True, all file_out IO operations will be awaited.
    """
    result = None
    with tarfile.open(fileobj=file_in) as tfile_in:
        for tarinfo in tfile_in:
            if tarinfo.name == name:
                result = await chunk_file(
                    tfile_in.extractfile(tarinfo),
                    file_out,
                    file_in_is_async=False,
                    file_out_is_async=file_out_is_async,
                )
                break
    return result


def file_exists_in_tar(file_in, name: str):
    """
    Checks if a file exists in a given tar archive.

    Args:
        file_in: The input file (tar).
        name: The name of the file for which to check existance.

    Returns:
        bool: True if the file exists, False otherwise.
    """
    with tarfile.open(fileobj=file_in) as tfile_in:
        for tarinfo in tfile_in:
            if tarinfo.name == name:
                return True
    return False


async def gunzip(path: Path, file_out, file_out_is_async: bool = True) -> UtilChunkFile:
    """
    Uncompresses a given gzip archive.

    Args:
        path: Path to the gzipped file.
        file_out: The output file.
        file_out_is_async: If True, all file_out IO operations will be awaited.

    Returns:
        dict: as defined by :func:~docker_sign_verify.Utils._chunk_file.
    """
    # TODO: Implement an async GzipFile ...
    with gzip.GzipFile(filename=path, mode="rb") as file_in:
        return await chunk_file(
            file_in,
            file_out,
            file_in_is_async=False,
            file_out_is_async=file_out_is_async,
        )
