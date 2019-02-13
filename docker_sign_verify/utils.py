#!/usr/bin/env python

"""Utility classes."""

import gzip
import hashlib
import io
import os
import shutil
import tarfile
import tempfile
import time

from typing import Dict

CHUNK_SIZE = 4096


class FormattedSHA256(str):
    """A algorithm prefixed SHA256 hash value."""

    def __new__(cls, sha256: str):
        if not sha256 or len(sha256) != 64:
            raise ValueError(sha256)
        obj = super().__new__(cls, "sha256:{0}".format(sha256))
        obj.sha256 = sha256
        return obj

    @staticmethod
    def parse(digest: str):
        """
        Initializes a FormattedSHA256 from a given SHA256 digest value.

        Args:
            digest: A SHA256 digest value in form SHA256:<digest value>.

        Returns:
            The newly initialized object.
        """
        if not digest or not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError(digest)
        return FormattedSHA256(digest[7:])


def _chunk_file(file_in, file_out) -> Dict:
    """
    Copies from one file to another in chunks.

    Args:
        file_in: The input file.
        file_out: The output file.

    Returns:
        dict:
            digest: The SHA256 digest value of the output file.
            size: Size of the output file in bytes.
    """
    size = 0
    hasher = hashlib.sha256()
    while True:
        chunk = file_in.read(CHUNK_SIZE)
        if not chunk:
            break
        file_out.write(chunk)
        size += len(chunk)
        hasher.update(chunk)
    file_out.flush()

    # Not all file object are native ...
    try:
        os.fsync(file_out.fileno())
    # pylint: disable=bare-except
    except:
        ...

    # Be kind, rewind ...
    file_out.seek(0)

    return {"digest": "sha256:{0}".format(hasher.hexdigest()), "size": size}


def must_be_equal(
    expected, actual, msg: str = "Actual value does not match expected value"
):
    """
    Compares two values and raises an exception if they are not equal.

    Args:
        expected: The expected value.
        actual: The actual value.
        msg: Message describing the context of the comparison.
    """
    if actual != expected:
        raise RuntimeError("{0}: {1} != {2}".format(msg, actual, expected))


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


def formatted_digest(data: bytes) -> FormattedSHA256:
    """
    Returns the algorithm prefixed digest value of given data.

    Args:
        data: The data for which to calculate the digest value.

    Returns:
        The digest value of the data in the format <hast type>:<digest value>.
    """
    return FormattedSHA256(hashlib.sha256(data).hexdigest())


def copy_file(file_in, file_out) -> Dict:
    """
    Copies from one file to another.

    Args:
        file_in: The input file.
        file_out: The output file.

    Returns:
        dict: as defined by :func:~docker_sign_verify.Utils._chunk_file.
    """
    return _chunk_file(file_in, file_out)


def read_file(path) -> bytes:
    """
    Retrieves the entire contents of a file.

    Args:
        path: Absolute path of the file to be read.

    Returns:
        The file content.
    """
    bytesio = io.BytesIO()
    with path.open(mode="rb") as file:
        copy_file(file, bytesio)
    return bytesio.read()


def write_file(path, content: bytes) -> Dict:
    """
    Assigns the entire contents of a file.

    Args:
        path: Absolute path of the file to be assigned.
        content: The content to be assigned.

    Returns:
        dict: as defined by :func:~docker_sign_verify.Utils.copy_file.
    """
    bytesio = io.BytesIO(content)
    with path.open(mode="wb") as file:
        return copy_file(bytesio, file)


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


def tar_delete_file(file_out, name: str):
    """
    Removes a file from a given tar archive on disk.

    Args:
        file_out: The output file.
        name: The name of the file to be removed.
    """
    with tempfile.TemporaryFile() as tmp:
        with tarfile.open(fileobj=file_out) as tfile_in:
            with tarfile.open(fileobj=tmp, mode="w:") as tfile_out:
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


def tar(file_out, name: str, file_in):
    """
    Adds a file to a given tar archive on disk to disk.

    Args:
        file_out: The output file (tar).
        name: The name of the file to be added.
        file_in: The input file.
    """
    with tarfile.TarFile("tar-archive", "a", file_out) as tfile_out:
        tarinfo = tfile_out.gettarinfo(None, name, file_in)
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = ""
        tarinfo.mode = 0o0644
        tfile_out.addfile(tarinfo, file_in)


def untar(file_in, name: str, file_out):
    """
    Extracts a file from a given tar archive.

    Args:
        file_in: The input file (tar).
        name: The name of the file to be extracted.
        file_out: The output file.
    """
    result = None
    with tarfile.open(fileobj=file_in) as tfile_in:
        for tarinfo in tfile_in:
            if tarinfo.name == name:
                result = _chunk_file(tfile_in.extractfile(tarinfo), file_out)
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


def gunzip(file_in, file_out) -> Dict:
    """
    Uncompresses a given gzip archive.

    Args:
        file_in: The input file (gz)
        file_out: The output file.

    Returns:
        dict: as defined by :func:~docker_sign_verify.Utils._chunk_file.
    """
    with gzip.GzipFile(fileobj=file_in, mode="rb") as gfile_in:
        return _chunk_file(gfile_in, file_out)
