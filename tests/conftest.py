#!/usr/bin/env python

"""Configures execution of pytest."""

import pytest

# https://stackoverflow.com/questions/51883573/using-a-command-line-option-in-a-pytest-skip-if-condition


def pytest_addoption(parser):
    """pytest addoption."""
    parser.addoption(
        "--allow-online",
        action="store_true",
        default=False,
        help="Allow execution of online tests.",
    )


def pytest_collection_modifyitems(config, items):
    """pytest collection modifier."""
    if config.getoption("--allow-online"):
        return

    skip_online = pytest.mark.skip(
        reason="Execution of online tests requires --allow-online option."
    )
    for item in items:
        if "online" in item.keywords:
            item.add_marker(skip_online)

def pytest_configure(config):
    """pytest configuration hook."""
    config.addinivalue_line("markers", "online: allow execution of online tests.")
