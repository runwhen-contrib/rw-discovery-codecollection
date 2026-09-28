.PHONY: install schemas test lint fmt fmt-check vectors

install:
	python3 -m pip install -e ".[dev]"

schemas:
	python3 scripts/export_schemas.py

test:
	python3 -m pytest -q

lint:
	ruff check .

fmt:
	ruff format .

fmt-check:
	ruff format --check .

# Validates every JMESPath expression in packs/kubernetes/pack.yaml compiles,
# and that the chain vectors round-trip. Also runs as part of `make test`;
# this target exists so CI/local dev can run it in isolation and fast.
vectors:
	python3 -m pytest -q tests/test_pack_yaml.py tests/test_chain_vectors.py
