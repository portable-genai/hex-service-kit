PY ?= .venv/bin/python

.PHONY: help install lock lint format-check typecheck test gate clean

help:
	@echo "install       install the package with its dev extra (editable)"
	@echo "lock          recompile requirements-dev.lock from pyproject.toml (needs uv + network)"
	@echo "lint          ruff check"
	@echo "format-check  ruff format --check"
	@echo "typecheck     mypy --strict over src"
	@echo "test          pytest, excluding integration"
	@echo "gate          the hard gate: all of the above, offline"

# The LOCKED install, which is what CI performs. `make install` and the hosted gate therefore
# agree about versions; an unlocked resolve is an authoring step, not a gate step.
install:
	$(PY) -m pip install -r requirements-dev.lock
	$(PY) -m pip install --no-deps -e .

# Authoring only: needs uv and network. Run it after any dependency change and commit the result.
lock:
	uv pip compile --quiet --extra dev pyproject.toml -o requirements-dev.lock

lint:
	$(PY) -m ruff check src tests

format-check:
	$(PY) -m ruff format --check src tests

typecheck:
	$(PY) -m mypy src

test:
	$(PY) -m pytest -m 'not integration'

# The hard gate. Everything here runs offline: this is a library with no network call and no
# clock of its own, so a green gate on a disconnected host means what it means anywhere else.
gate: lint format-check typecheck test
	@echo "GATE: PASS"

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache build dist
