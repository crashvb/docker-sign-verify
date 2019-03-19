#! /usr/bin/make -f

-include makefile.config

.PHONY: build clean default deploy purge sign test test_code test_package venv verify

tmpdir:=$(shell mktemp --directory)

default: build

black:
	python -m black .

build:
	python setup.py bdist_wheel sdist

sign:
	find dist -type f \( -iname "*.tar.gz" -o -iname "*.whl" \) -exec gpg --armor --detach-sig --sign {} \;

verify:
	find dist -type f -iname "*.asc" -exec gpg --verify {} \;

test:
	python -m pytest --log-cli-level info

test_code:
	# Note: https://github.com/PyCQA/pylint/issues/289
	python -m pylint --disable C0330 --max-line-length=120 docker_sign_verify

test_package: build
	python -m venv $(tmpdir)

	cd /tmp
	$(tmpdir)/bin/python -m pip install $(PWD)/dist/*.tar.gz pytest
	$(tmpdir)/bin/python -m pytest
	rm --force --recursive $(tmpdir)

deploy: clean build sign
	python -m twine upload dist/*

deploy_test: clean build sign
	python -m twine upload --repository testpypi dist/*

.venv:
	python -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install --editable .[dev]

venv: .venv

clean:
	rm --force --recursive .eggs build dist *.egg-info
	find . -type f -name "*.pyc" -delete
	find . -type d -name __pycache__ -delete

purge: clean
	rm --force --recursive .venv
