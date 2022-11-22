SHELL   := /bin/bash
PYTHON  ?= python3

export PYTHONWARNINGS := default

.PHONY: all test lint lint-extra

all:

test: lint lint-extra

lint:
	flake8 *.py
	pylint *.py

lint-extra:
	mypy *.py
