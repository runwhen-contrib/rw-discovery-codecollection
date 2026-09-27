#!/usr/bin/env python3
"""Exports JSON Schema from rwdiscovery's pydantic models into
capabilities/k8s-discovery/schemas/. Per the RunWhen capability manifest
format's convention that a task output's schema is exported, not
hand-written -- generated from the SDK's models at build time so it cannot
drift from the code. (Here it's rwdiscovery's own output models, the same
convention rw-checks-codecollection applies to its runwhen_capability
models.)

Each model carries its own `SCHEMA_VERSION` class attribute (right next to
the model, so a developer changing its shape sees it) -- this script writes
`<name>.v<SCHEMA_VERSION>.json`, never overwriting an already-published file.
A published schema file never changes once committed (see
docs/platform-contract.md's "versioned, immutable schemas" section and
scripts/check_schema_immutability.py, which enforces it in CI): bumping a
model's SCHEMA_VERSION and re-running this script is how a shape change gets
published -- the old, lower-numbered file is left exactly as it was, and
`capabilities/k8s-discovery/manifest.yaml`'s `schema:` ref moves to the new
one.

Usage: python3 scripts/export_schemas.py   (or `make schemas`)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pydantic import TypeAdapter  # noqa: E402

from rwdiscovery.models import DiscoverySummary, K8sObjectResult  # noqa: E402

CAPABILITY_DIR = REPO_ROOT / "capabilities" / "k8s-discovery"

# name -> model. The published filename is derived from each model's own
# SCHEMA_VERSION below, not hardcoded here, so bumping the version is the
# only edit a shape change needs.
_MODELS = {
    "discovery_summary": DiscoverySummary,
    "k8s_object": K8sObjectResult,
}

SCHEMAS = {f"{name}.v{model.SCHEMA_VERSION}.json": TypeAdapter(model).json_schema() for name, model in _MODELS.items()}


def main() -> None:
    out_dir = CAPABILITY_DIR / "schemas"
    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, schema in SCHEMAS.items():
        out_path = out_dir / filename
        out_path.write_text(json.dumps(schema, indent=2) + "\n")
        print(f"wrote {out_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
