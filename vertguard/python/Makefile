# VertGuard ML service Makefile.
# Targets: proto, test, lint, typecheck, run.

PY ?= python

.PHONY: proto test lint typecheck run install-dev

proto:
	bash scripts/gen_proto.sh

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

typecheck:
	$(PY) -m mypy vertguard_ml

run:
	$(PY) -m vertguard_ml.server

install-dev:
	$(PY) -m pip install -e .[dev]
