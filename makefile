#!/usr/bin/make -f

include makefile.config
-include makefile.config.local

.PHONY: black build clean default deploy deploy-test purge release sign test test-all test-all-verbose test-code test-coverage test-coverage-all test-coverage-all-verbose test-coverage-verbose test-package test-verbose venv .venv verify

package_folder := $(shell sed --expression='s/^.*name="\(.*\)",/\1/p' --quiet setup.py)
package_name := $(shell sed --expression='s/_/-/g' --expression='s/^.*name="\(.*\)",/\1/p' --quiet setup.py)

default: build

black:
	python -m black .

build:
	python setup.py bdist_wheel sdist
	tar --file dist/*.tar.gz --list --verbose
	unzip -l dist/*.whl

deploy: clean build sign
	python -m twine upload dist/*

deploy-test: clean build sign
	python -m twine upload --repository testpypi dist/*

release:
	@[ "X$(shell git status --porcelain 2>&1)" = "X" ] || (echo "GIT work tree is dirty!" && /bin/false)
	@echo "Detected package: $(package_name)"
	$(eval version_current := $(shell sed --expression='s/^__version__ = "\(.*\)"/\1/p' --quiet */__init__.py))
	@echo "Detected current version as: $(version_current)"
	$(eval version_release := $(shell echo "$(version_current)" | sed --expression='s/.dev0//g'))
	@echo "Setting release version to: $(version_release)"
	@sed --expression='s/"$(version_current)"$$/"$(version_release)"/' --in-place */__init__.py
	@git commit --all --message "prepare release $(package_name)-$(version_release)"
	@git tag --message="release $(package_name)-$(version_release)" --sign "$(package_name)-$(version_release)"

	$(eval version_next := $(shell echo "$(version_release)" | awk --field-separator=. --assign OFS=. 'NF==1{print ++$$NF}; NF>1{$$NF=sprintf("%0*d", length($$NF), ($$NF+1)); print}'))
	$(eval version_next := $(version_next).dev0)
	@echo "Setting next version to: $(version_next)"
	@sed --expression='s/"$(version_release)"$$/"$(version_next)"/' --in-place */__init__.py
	@git commit --all --message "prepare for next development iteration"


sign:
	$(eval keyid := $(shell git config --get user.signingkey))
	find dist -type f \( -iname "*.tar.gz" -o -iname "*.whl" \) -exec gpg --armor --detach-sig --local-user=$(keyid) --sign {} \;

test:
	python -m pytest --cov=$(package_folder) --cov-report= --log-cli-level info $(args)

test-all:
	python -m pytest --cov=$(package_folder) --cov-report= --log-cli-level info $(test_all_args) $(args)

test-all-verbose:
	python -m pytest --cov=$(package_folder) --cov-report= --log-cli-level debug $(test_all_args) $(args)

test-code:
	python -m pylint --disable=$(pylint_disable) --max-line-length=120 $(package_folder) tests

test-coverage: test
	coverage report --fail-under=80

test-coverage-all: test-all
	coverage report --fail-under=80

test-coverage-all-verbose: test-all-verbose
	coverage report --fail-under=80

test-coverage-verbose: test-verbose
	coverage report --fail-under=80

test-package: build
	$(eval tmpdir := $(shell mktemp --directory))
	python -m venv $(tmpdir)

	cd /tmp
	$(tmpdir)/bin/python -m pip install $(PWD)/dist/*.tar.gz pytest
	$(tmpdir)/bin/python -m pytest
	rm --force --recursive $(tmpdir)

test-verbose:
	python -m pytest -r sx --cov=$(package_folder) --cov-report= --log-cli-level debug $(args)

.venv:
	python -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install --editable .[dev]

venv: .venv

verify:
	find dist -type f -iname "*.asc" -exec gpg --verify {} \;

clean:
	rm --force --recursive .coverage .eggs build dist *.egg-info
	find . -type f -name "*.pyc" -delete
	find . -type d -name __pycache__ -delete

purge: clean
	rm --force --recursive .venv
