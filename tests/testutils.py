#!/usr/bin/env python

"""Utility classes."""

import hashlib

from pathlib import Path
from typing import Union

import aiofiles

from docker_registry_client_async.formattedsha256 import FormattedSHA256
from docker_registry_client_async.utils import CHUNK_SIZE


def get_test_data_path(request, name) -> Path:
    """Helper method to retrieve the path of test data."""
    return Path(request.fspath).parent.joinpath("data").joinpath(name)


def get_test_data(request, klass, name, mode="rb") -> Union[bytes, str]:
    """Helper method to retrieve test data."""
    key = "{0}/{1}".format(klass, name)
    result = request.config.cache.get(key, None)
    if result is None:
        path = get_test_data_path(request, name)
        with open(path, mode) as file:
            result = file.read()
            # TODO: How do we / Should we serialize binary data?
            # request.config.cache.set(key, result)
    return result


async def hash_file(path: Path) -> FormattedSHA256:
    """Returns the sha256 digest value for the content of a given file."""
    hasher = hashlib.sha256()
    async with aiofiles.open(path, mode="r+b") as file:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return FormattedSHA256(hasher.hexdigest())
