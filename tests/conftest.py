#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Configures execution of pytest."""

from typing import Dict, Generator, TypedDict

import pytest

from click.testing import CliRunner
from docker_registry_client_async import (
    DockerMediaTypes,
    FormattedSHA256,
    ImageName,
)
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


class TypingGetTestData(TypedDict):
    # pylint: disable=missing-class-docstring
    image: str
    tag: str
    digests: Dict[str, FormattedSHA256]


class TypingKnownGoodImage(TypingGetTestData):
    # pylint: disable=missing-class-docstring
    image_name: ImageName


def get_test_data_registryv2() -> Generator[TypingGetTestData, None, None]:
    """Dynamically initializes test data for a local mutable registry."""
    images = [
        {
            "image": "library/busybox",
            "tag": "1.30.1",
            "digests": {
                # Note: Extracted 4fe88... from the manifest list for 'amd64'.
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100"
                ),
                # Note: Extracted 4b6ad... from the 'RepoDigests' field (docker-inspect), after pulling by tag.
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "4b6ad3a68d34da29bf7c8ccb5d355ba8b4babcad1f99798204e7abb43e54ee3d"
                ),
            },
            "tag_resolves_to_manifest_list": True,
        },
        {
            "image": "library/python",
            "tag": "3.7.2-slim-stretch",
            "digests": {
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "0005ba40bf87e486d7061ca0112123270e4a6088b5071223c8d467db3dbba908"
                ),
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "78320634b63efb52f591a7d69d5a50076ce76e7b72c4b45c1e4ddad90c39870a"
                ),
            },
            "tag_resolves_to_manifest_list": True,
        },
    ]
    for image in images:
        yield image


def get_test_data_archive() -> Generator[TypingGetTestData, None, None]:
    """Dynamically initializes test data for a local mutable registry."""
    images = [
        # docker save library/busybox@sha256:4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100 > \
        #   archive.digest_only.tar
        # docker save library/busybox:1.30.1 > archive.tag_only.tar
        {
            "image": "library/busybox",
            "digest": "64f5d945efcc0f39ab11b3cd4ba403cc9fefe1fa3613123ca016cf3708e8cafb",
            "resource": "archive.digest_only.tar",
            "_digests": {
                "changeset_manifest": "085587963d46bdf491f864ef64a2aa30f0dadb8bf695b7a1ae2ffada62651dfc",
                "manifest_64f5d945efcc0f39ab11b3cd4ba403cc9fefe1fa3613123ca016cf3708e8cafb": "ce342a56fdeb0dbf17f8e0d33b5df0ab69e75b53182ba60f06285ec2ddc48dbe",
            },
        },
        {
            "image": "library/busybox",
            "tag": "1.30.1",
            "resource": "archive.tag_only.tar",
            "_digests": {
                "changeset_manifest": "e9b3b249bd0b919a7ce6ccbd23d8adb0b91247546fcfe527d74ed2270b9e227d",
                "manifest_1.30.1": "2c7e2209dc919d046c1111c5082c819f40c8c25ee252f4b6fc2a03695c66a552",
            },
        },
        {
            "image": "library/busybox",
            "tag": "1.30.1",
            "digest": "64f5d945efcc0f39ab11b3cd4ba403cc9fefe1fa3613123ca016cf3708e8cafb",
            "resource": "archive.tag_only.tar",
            "_digests": {
                "changeset_manifest": "e9b3b249bd0b919a7ce6ccbd23d8adb0b91247546fcfe527d74ed2270b9e227d",
                "manifest_64f5d945efcc0f39ab11b3cd4ba403cc9fefe1fa3613123ca016cf3708e8cafb": "2c7e2209dc919d046c1111c5082c819f40c8c25ee252f4b6fc2a03695c66a552",
                "manifest_1.30.1": "2c7e2209dc919d046c1111c5082c819f40c8c25ee252f4b6fc2a03695c66a552",
            },
        },
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


@pytest.fixture
def clirunner() -> Generator[CliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


@pytest.fixture(params=get_test_data_registryv2())
def known_good_image(
    docker_registry_secure: DockerRegistrySecure, request
) -> TypingKnownGoodImage:
    """Provides 'known good' metadata for a local image that can be modified."""
    image_name = ImageName.parse(request.param["image"])
    image_name.endpoint = docker_registry_secure.endpoint
    request.param["image"] = str(image_name)

    manifest_digest = request.param["digests"][
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    ]
    request.param["image_name"] = ImageName.parse(
        f"{request.param['image']}:{request.param['tag']}@{manifest_digest}"
    )

    return request.param


@pytest.fixture
def runner() -> Generator[DSVCliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = DSVCliRunner()
    with runner.isolated_filesystem():
        yield runner
