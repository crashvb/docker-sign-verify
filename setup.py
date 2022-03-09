#!/usr/bin/env python

import os
import re

from setuptools import setup, find_packages


def find_version(*segments):
    root = os.path.abspath(os.path.dirname(__file__))
    abspath = os.path.join(root, *segments)
    with open(abspath, "r") as file:
        content = file.read()
    match = re.search(r"^__version__ = ['\"]([^'\"]+)['\"]", content, re.MULTILINE)
    if match:
        return match.group(1)
    raise RuntimeError("Unable to find version string!")


setup(
    author="Richard Davis",
    author_email="crashvb@gmail.com",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    description="A utility that can be used to sign and verify docker images.",
    entry_points="""
        [console_scripts]
        dsv=docker_sign_verify.scripts.dsv:cli
    """,
    extras_require={
        "dev": [
            "black",
            "docker",
            "docker-compose",
            "lovely-pytest-docker",
            "pylint",
            "pytest",
            "pytest-asyncio",
            "pytest-docker-registry-fixtures",
            "pytest-docker-squid-fixtures>=0.1.2",
            "pytest-gnupg-fixtures",
            "pytest-select",
            "twine",
            "wheel",
        ]
    },
    include_package_data=True,
    install_requires=[
        "aiofiles",
        "aiohttp",
        "aiotempfile",
        "canonicaljson",
        "docker-registry-client-async>=0.2.3",
        "click",
        "pycryptodome",
    ],
    keywords="docker docker-sign docker-verify integrity sign signatures verify",
    license="Apache License 2.0",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    name="docker_sign_verify",
    packages=find_packages(),
    project_urls={
        "Bug Reports": "https://github.com/crashvb/docker-sign-verify/issues",
        "Source": "https://github.com/crashvb/docker-sign-verify",
    },
    tests_require=[
        "docker",
        "docker-compose",
        "lovely-pytest-docker",
        "pytest",
        "pytest-asyncio",
        "pytest-docker-registry-fixtures",
        "pytest-docker-squid-fixtures",
        "pytest-gnupg-fixtures",
    ],
    test_suite="tests",
    url="https://github.com/crashvb/docker-sign-verify",
    version=find_version("docker_sign_verify", "__init__.py"),
)
