# Atlas - AWS Cloud Adversary Emulation
# Run in lab accounts only.

PYTHON ?= python
UV ?= uv

.PHONY: install install-dev lint test test-cov run run-dry clean help

help:
	@echo "Targets: install, install-dev, lint, test, test-cov, run, run-dry, clean"

install:
	$(UV) pip install -e .

install-dev:
	$(UV) pip install -e ".[dev]"
	$(UV) pip install pre-commit
	pre-commit install

lint:
	ruff check src tests
	ruff format --check src tests
	mypy src --no-error-summary 2>/dev/null || true

format:
	ruff format src tests
	ruff check --fix src tests

test:
	$(PYTHON) -m pytest tests -v

test-cov:
	$(PYTHON) -m pytest tests -v --cov=src/atlas --cov-report=term-missing

run:
	$(PYTHON) -m atlas.cli.main run campaigns/discovery.yaml --output-dir output

run-dry:
	$(PYTHON) -m atlas.cli.main run campaigns/discovery.yaml --dry-run --output-dir output

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
