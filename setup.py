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
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    description="A utility that can be used to sign and verify docker images.",
    entry_points="""
        [console_scripts]
        docker-sign=docker_sign_verify.scripts.docker_sign:cli
        docker-verify=docker_sign_verify.scripts.docker_verify:cli
    """,
    extras_require={"dev": ["black", "pylint", "twine", "pytest", "wheel"]},
    include_package_data=True,
    install_requires=[
        "canonicaljson",
        "click",
        "gnupg",
        "pycryptodome",
        "requests",
        "www_authenticate",
    ],
    keywords="docker docker-sign docker-verify integrity sign signatures verify",
    license="Apache License 2.0",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    name="docker_sign_verify",
    packages=find_packages(),
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    test_suite="tests",
    url="https://pypi.org/project/docker-sign-verify/",
    version=find_version("docker_sign_verify", "__init__.py"),
)
