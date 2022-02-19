#!/usr/bin/env python

# pylint: disable=line-too-long,redefined-outer-name

"""Configures execution of pytest."""

from typing import Dict, Generator, NamedTuple

import pytest

from click.testing import CliRunner
from docker_registry_client_async import (
    DockerMediaTypes,
    FormattedSHA256,
    ImageName,
)
from pytest_asyncio.plugin import Mode
from pytest_docker_registry_fixtures import DockerRegistrySecure

from .stubs import DSVCliRunner


_pytestmark = [
    pytest.mark.push_image(
        # "library/busybox:1.30.1",
        "library/busybox@sha256:4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100",
        "library/busybox@sha256:abc043b5132f825e44eefffc35535b1f24bd3f1bb60b11943863563a46795fdc",
        "library/busybox@sha256:07717dd5f074de0cf4f7ca8f635cb63aef63d789f15a22ab482a3d27a0a1f881",
        "library/busybox@sha256:8dfe92e22300734a185375b6316d01aa1a2b0623d425a5e6e406771ba5642bf1",
        "library/busybox@sha256:3bdba83255bf7c575e31e129b2ddf1c0c32382e112cb051af6c5143c24a5ddbd",
        "library/busybox@sha256:bb87f507b42a6efe6f1d5382c826f914673a065f4d777b54b52f5414d688837a",
        "library/busybox@sha256:a09f03056efb5d3facb5077a9e58e83e9bba74ad4d343b2afa92c70b5ae01e2b",
        "library/busybox@sha256:0b671b6a323d86aa6165883f698b557ca257c3a3ffa1e3152ffb6467e7ac11b3",
        "library/busybox@sha256:4b6ad3a68d34da29bf7c8ccb5d355ba8b4babcad1f99798204e7abb43e54ee3d",  # ManifestList
        # "library/python:3.7.2-slim-stretch",
        "library/python@sha256:0005ba40bf87e486d7061ca0112123270e4a6088b5071223c8d467db3dbba908",
        "library/python@sha256:09001905f918a977427cc6931a1cac84a8645b1ac2011fd3f40f625daf9a7fb1",
        "library/python@sha256:2d127b64fbb7a58ee8eb2c321f1bbd14548ab3191009cca7845b81155c9067bf",
        "library/python@sha256:59768566a74724d0feeca46cf4f21fd73850b56b8cbbc9dc46ef2f0e179064c5",
        "library/python@sha256:7505b822f9430bb8887037085e8b40d88ee02a424c075137f7d5b148a9e7131d",
        "library/python@sha256:de66a6835cfa722611fad3111edad211a66b489fd0a74db67487d860001fdc0c",
        "library/python@sha256:7d925740cfb767f08105b764b8126e29cd3bb6654a759aad09929206644c7bac",
        "library/python@sha256:78320634b63efb52f591a7d69d5a50076ce76e7b72c4b45c1e4ddad90c39870a",  # ManifestList
    ),
]


class TypingGetTestData(NamedTuple):
    # pylint: disable=missing-class-docstring
    digests: Dict[str, FormattedSHA256]
    image: str
    tag: str
    tag_resolves_to_manifest_list: bool


class TypingKnownGoodImage(NamedTuple):
    # pylint: disable=missing-class-docstring
    digests: Dict[str, FormattedSHA256]
    image: str
    image_name: ImageName
    tag: str


def get_test_data() -> Generator[TypingGetTestData, None, None]:
    """Dynamically initializes test data for a local mutable registry."""
    images = [
        TypingGetTestData(
            image="library/busybox",
            tag="1.30.1",
            digests={
                # Note: Extracted 4fe88... from the manifest list for 'amd64'.
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100"
                ),
                # Note: Extracted 4b6ad... from the 'RepoDigests' field (docker-inspect), after pulling by tag.
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "4b6ad3a68d34da29bf7c8ccb5d355ba8b4babcad1f99798204e7abb43e54ee3d"
                ),
            },
            tag_resolves_to_manifest_list=True,
        ),
        TypingGetTestData(
            image="library/python",
            tag="3.7.2-slim-stretch",
            digests={
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "0005ba40bf87e486d7061ca0112123270e4a6088b5071223c8d467db3dbba908"
                ),
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "78320634b63efb52f591a7d69d5a50076ce76e7b72c4b45c1e4ddad90c39870a"
                ),
            },
            tag_resolves_to_manifest_list=True,
        ),
    ]
    for image in images:
        yield image


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

    config.option.asyncio_mode = Mode.AUTO


@pytest.fixture
def clirunner() -> Generator[CliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


@pytest.fixture(params=get_test_data())
def known_good_image(
    docker_registry_secure: DockerRegistrySecure, request
) -> TypingKnownGoodImage:
    """Provides 'known good' metadata for a local image that can be modified."""
    image_name = ImageName.parse(request.param.image)
    image_name.endpoint = docker_registry_secure.endpoint
    manifest_digest = request.param.digests[DockerMediaTypes.DISTRIBUTION_MANIFEST_V2]
    return TypingKnownGoodImage(
        digests=request.param.digests,
        image=str(image_name),
        image_name=ImageName.parse(
            f"{str(image_name)}:{request.param.tag}@{manifest_digest}"
        ),
        tag=request.param.tag,
    )


@pytest.fixture(params=get_test_data())
def known_good_image_proxy(
    docker_registry_secure: DockerRegistrySecure, request
) -> TypingKnownGoodImage:
    """Provides 'known good' metadata for a local image that can be modified."""
    image_name = ImageName.parse(request.param.image)
    # Because the squid fixture is also running inside of docker-compose, it will be issued separate network stacks and
    # trying to resolve the registry (HTTP CONNECT) using 127.0.0.1 as the endpoint address will not work. Instead, use
    # the docker-compose default network, and the internal service port.
    image_name.endpoint = docker_registry_secure.endpoint_name
    manifest_digest = request.param.digests[DockerMediaTypes.DISTRIBUTION_MANIFEST_V2]
    return TypingKnownGoodImage(
        digests=request.param.digests,
        image=str(image_name),
        image_name=ImageName.parse(
            f"{str(image_name)}:{request.param.tag}@{manifest_digest}"
        ),
        tag=request.param.tag,
    )


@pytest.fixture
def runner() -> Generator[DSVCliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = DSVCliRunner()
    with runner.isolated_filesystem():
        yield runner
