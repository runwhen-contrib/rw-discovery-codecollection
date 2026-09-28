"""Guards the RunWhen capability manifest format's "schema is exported,
not hand-written -- generated from the SDK's models at build time so it
cannot drift from the code" convention: every schema file listed under
[tool.rwtask.schemas] in pyproject.toml must match what `rwtask schemas`
would generate from rwdiscovery.models right now. Mirrors
rw-checks-codecollection's tests/test_schemas.py.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from runwhen_capability.schemas import load_targets, render

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPABILITY_DIR = REPO_ROOT / "capabilities" / "k8s-discovery"
TARGETS = [t for t in load_targets(REPO_ROOT) if t.capability_dir == "capabilities/k8s-discovery"]
SCHEMAS = {t.filename for t in TARGETS}


def test_checked_in_schemas_match_the_current_models():
    stale = []
    for target in TARGETS:
        path = REPO_ROOT / target.relpath
        if not path.is_file() or path.read_text() != render(target, REPO_ROOT):
            stale.append(target.relpath)
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
