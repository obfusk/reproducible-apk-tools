SHELL   := /bin/bash
PYTHON  ?= python3

SCRIPTS := fix-services-newlines.py fix-ordering.py

export PYTHONWARNINGS := default

.PHONY: all test lint lint-extra

all:

test: lint lint-extra

lint:
	flake8 $(SCRIPTS)
	pylint $(SCRIPTS)

lint-extra:
	mypy $(SCRIPTS)
