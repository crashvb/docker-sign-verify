#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Configures execution of pytest."""

from typing import Generator

import pytest

from click.testing import CliRunner

from .stubs import DSVCliRunner

# https://stackoverflow.com/questions/51883573/using-a-command-line-option-in-a-pytest-skip-if-condition


def pytest_addoption(parser):
    """pytest addoption."""
    parser.addoption(
        "--allow-online",
        action="store_true",
        default=False,
        help="Allow execution of online tests.",
    )
    parser.addoption(
        "--allow-online-modification",
        action="store_true",
        default=False,
        help="Allow modification of online content (implies --allow-online).",
    )


def pytest_collection_modifyitems(config, items):
    """pytest collection modifier."""

    skip_online = pytest.mark.skip(
        reason="Execution of online tests requires --allow-online option."
    )
    skip_online_modification = pytest.mark.skip(
        reason="Modification of online content requires --allow-online-modification option."
    )
    for item in items:
        if "online_modification" in item.keywords and not config.getoption(
            "--allow-online-modification"
        ):
            item.add_marker(skip_online_modification)
        elif (
            "online" in item.keywords
            and not config.getoption("--allow-online")
            and not config.getoption("--allow-online-modification")
        ):
            item.add_marker(skip_online)


def pytest_configure(config):
    """pytest configuration hook."""
    config.addinivalue_line("markers", "online: allow execution of online tests.")
    config.addinivalue_line(
        "markers", "online_modification: allow modification of online content."
    )


@pytest.fixture
def clirunner() -> Generator[CliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


@pytest.fixture
def runner() -> Generator[DSVCliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = DSVCliRunner()
    with runner.isolated_filesystem():
        yield runner
