"""Guards the RunWhen capability manifest format's "schema is exported,
not hand-written -- generated from the SDK's models at build time so it
cannot drift from the code" convention: every checked-in
capabilities/k8s-discovery/schemas/*.json file must match what
scripts/export_schemas.py would generate from rwdiscovery.models right
now. Mirrors rw-checks-codecollection's tests/test_schemas.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from export_schemas import CAPABILITY_DIR, SCHEMAS  # noqa: E402


def test_checked_in_schemas_match_the_current_models():
    stale = []
    for filename, schema in SCHEMAS.items():
        path = CAPABILITY_DIR / "schemas" / filename
        on_disk = json.loads(path.read_text())
        if on_disk != schema:
            stale.append(str(path.relative_to(REPO_ROOT)))
    assert stale == [], f"schema(s) out of date with the models, run `make schemas`: {stale}"


def test_every_manifest_schema_reference_is_registered():
    manifest = yaml.safe_load((CAPABILITY_DIR / "manifest.yaml").read_text())
    unregistered = []
    for task in manifest.get("tasks", []):
        for output in task.get("outputs", {}).values():
            schema_ref = output.get("schema")
            if schema_ref and Path(schema_ref).name not in SCHEMAS:
                unregistered.append(f"task {task['name']!r}: {schema_ref}")
    assert unregistered == [], unregistered
