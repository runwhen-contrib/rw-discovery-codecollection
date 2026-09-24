#!/usr/bin/env python3
"""Exports JSON Schema from rwdiscovery's pydantic models into
capabilities/k8s-discovery/schemas/. Per the RunWhen capability manifest
format's convention that a task output's schema is exported, not
hand-written -- generated from the SDK's models at build time so it cannot
drift from the code. (Here it's rwdiscovery's own output models, the same
convention rw-checks-codecollection applies to its runwhen_capability
models.)

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
SCHEMAS = {
    "discovery_summary.json": TypeAdapter(DiscoverySummary).json_schema(),
    "k8s_object.json": TypeAdapter(K8sObjectResult).json_schema(),
}


def main() -> None:
    out_dir = CAPABILITY_DIR / "schemas"
    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, schema in SCHEMAS.items():
        out_path = out_dir / filename
        out_path.write_text(json.dumps(schema, indent=2) + "\n")
        print(f"wrote {out_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
