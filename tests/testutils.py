#!/usr/bin/env python

"""Utility classes."""

from pathlib import Path


def get_test_data_path(request, name):
    """Helper method to retrieve the path of test data."""
    return Path(request.fspath).parent.joinpath("data").joinpath(name)


def get_test_data(request, klass, name, mode="rb"):
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
