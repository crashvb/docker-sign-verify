#!/usr/bin/env python

"""CLI tests."""

from docker_sign_verify.scripts.docker_copy import cli as docker_copy_cli
from docker_sign_verify.scripts.docker_sign import cli as docker_sign_cli
from docker_sign_verify.scripts.docker_verify import cli as docker_verify_cli

from .testutils import runner


def test_docker_copy_empty(runner):
    """Test docker-copy CLI can be invoked."""
    result = runner.invoke(docker_copy_cli, ["registry"])
    assert "Usage:" in result.stdout
    assert result.exit_code != 0


def test_docker_sign_empty(runner):
    """Test docker-copy CLI can be invoked."""
    result = runner.invoke(docker_sign_cli, ["registry"])
    assert "Usage:" in result.stdout
    assert result.exit_code != 0


def test_docker_verify_empty(runner):
    """Test docker-copy CLI can be invoked."""
    result = runner.invoke(docker_verify_cli, ["registry"])
    assert "Usage:" in result.stdout
    assert result.exit_code != 0
