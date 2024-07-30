.PHONY: clean clean-build clean-pyc clean-test coverage dist docs help install style
.DEFAULT_GOAL := help

define BROWSER_PYSCRIPT
import os, webbrowser, sys

from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-venv clean-test clean-docs ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-venv: ## remove venv files
	rm -fr .venv

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

clean-docs: ## clean documentation generated
	rm -fr docsbuild

clean-wheelhouse: ## remove all wheelhouse
	rm -fr wheelhouse

venv: ## Create virtual environment
	rm -Rf .venv
	python3 -m venv .venv --prompt pysecureenclave
	/bin/bash -c "source .venv/bin/activate && pip install pip --upgrade && pip install -r requirements_dev.txt && pip install -e ."
	echo "Enter virtual environment using:\n\n\t$ source .venv/bin/activate\n"

venv-offline: ## Create virtual environment while offline
	rm -Rf .venv
	python3 -m venv .venv --prompt pyfletinventory
	/bin/bash -c "source .venv/bin/activate && pip install pip --upgrade --no-index --find-links wheelhouse && pip install -r requirements_dev.txt --no-index --find-links wheelhouse && pip install -e . --no-index --find-links wheelhouse"
	echo "Enter virtual environment using:\n\n\t$ source .venv/bin/activate\n"

wheelhouse: ## Gather wheels from internet for offline usage
	rm -Rf wheelhouse
	mkdir wheelhouse
	python -m pip download -r requirements.txt -d wheelhouse
	python -m pip download -r requirements_dev.txt -d wheelhouse

style: ## check style
	flake8 --max-line-length=120 --ignore=E128 pysecureenclave tests

test: ## run tests quickly with the default Python
	pytest

test-all: ## run tests on every Python version with tox
	tox

coverage: ## check code coverage quickly with the default Python
	coverage run --source pysecureenclave -m pytest
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

docs: clean-docs ## generate mkdocs documentation
	mkdocs build -d docsbuild
	$(BROWSER) docsbuild/index.html

docs-serve: ## compile the docs watching for changes
	mkdocs serve

dist: clean ## builds source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: clean ## install the package to the active Python's site-packages
	python setup.py install

dev: ## create a development library or cli from this package
	python setup.py develop
