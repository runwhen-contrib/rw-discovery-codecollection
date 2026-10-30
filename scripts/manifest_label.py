#!/usr/bin/env python3
"""Reads capabilities/k8s-discovery/manifest.yaml and prints the values the
Dockerfile bakes in as OCI labels, so the labels can never drift from the
manifest they describe -- the image itself carries its own manifest (and
every version of the JSON Schemas its task outputs reference) as OCI labels,
so the catalog can read them straight off the pushed image.

Besides the manifest bytes, this also bundles every file in the capability's
own `schemas/` directory into one JSON object -- keyed by its path relative
to the manifest's directory, normalised with posixpath.normpath (e.g.
`schemas/k8s_object.v1.json`) -- that becomes the com.runwhen.capability.
schemas.v1 label. That is the capability's whole published schema history,
not only the versions `manifest.yaml`'s tasks currently reference (see
docs/platform-contract.md's "versioned, immutable schemas" section): an old
run's result may still name a schema no task references any more, and the
label carries it regardless. The build still fails if any `tasks[*].
outputs.<name>.schema` reference (e.g. `./schemas/k8s_object.v1.json`) is
missing from the resulting map, is not valid JSON, is not a JSON object, or
whose path escapes the manifest's own directory -- a capability whose
manifest references no schema, and has no `schemas/` directory, gets an
empty value (no label content, but the key is still printed).

The final `image:` digest is a separate story -- it doesn't exist until
this image has been pushed, so it is resolved by CI *after* the push
(`docker buildx imagetools inspect`, the same two-step rw-checks-
codecollection's build-push.yaml uses for its own manifests) and is never
one of the values this script prints.

Usage (from the Dockerfile build, via `--build-arg`s computed from this
script's output):

    python3 scripts/manifest_label.py >> "$GITHUB_OUTPUT"
    # prints capability=..., capability_version=..., manifest_b64=..., schemas_b64=...
    docker build \
      --build-arg CAPABILITY=$capability \
      --build-arg CAPABILITY_VERSION=$capability_version \
      --build-arg MANIFEST_B64=$manifest_b64 \
      --build-arg SCHEMAS_B64=$schemas_b64 \
      -f Dockerfile.k8s-discovery .
"""

from __future__ import annotations

import base64
import json
import posixpath
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "capabilities" / "k8s-discovery" / "manifest.yaml"


class ManifestLabelError(RuntimeError):
    """Raised when a manifest-referenced output schema can't be resolved into the schemas label."""


def collect_schema_refs(manifest: dict) -> list[tuple[str, str, str]]:
    """Every (task name, output name, schema ref) for tasks[*].outputs[*].schema in the manifest."""
    refs: list[tuple[str, str, str]] = []
    for task in manifest.get("tasks") or []:
        task_name = task.get("name", "<unnamed task>")
        for output_name, output in (task.get("outputs") or {}).items():
            schema_ref = output.get("schema") if isinstance(output, dict) else None
            if schema_ref:
                refs.append((task_name, output_name, schema_ref))
    return refs


def _load_schema_object(schema_path: Path, where: str) -> dict:
    """Parse schema_path as JSON, raising ManifestLabelError (prefixed with `where`) if it's
    not valid JSON or not a JSON object."""
    try:
        parsed = json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestLabelError(f"{where} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ManifestLabelError(f"{where} must be a JSON object, got {type(parsed).__name__}")
    return parsed


def build_schemas_map(manifest: dict, manifest_dir: Path) -> dict[str, dict]:
    """Every *.json file under manifest_dir's schemas/ directory, parsed and keyed by its path
    relative to manifest_dir, normalised with posixpath.normpath (e.g.
    schemas/k8s_object.v1.json) -- the capability's whole published schema history, not only
    the versions the manifest currently references.

    Raises ManifestLabelError, naming the offending file, when a schemas/ file is not valid
    JSON or not a JSON object. Also raises ManifestLabelError, naming the offending
    task/output/path, when a tasks[*].outputs[*].schema reference is absolute, escapes
    manifest_dir via a '..' segment, or names a file that isn't in the resulting map.
    """
    schemas: dict[str, dict] = {}
    schemas_dir = manifest_dir / "schemas"
    if schemas_dir.is_dir():
        for schema_path in sorted(schemas_dir.glob("*.json")):
            key = posixpath.normpath(str(schema_path.relative_to(manifest_dir)))
            schemas[key] = _load_schema_object(schema_path, f"schema file {schema_path}")

    for task_name, output_name, schema_ref in collect_schema_refs(manifest):
        where = f"task {task_name!r} output {output_name!r} (schema: {schema_ref!r})"
        key = posixpath.normpath(schema_ref)
        if posixpath.isabs(key) or key == ".." or key.startswith("../"):
            raise ManifestLabelError(
                f"{where}: schema path must be relative and stay under the manifest's own directory"
            )
        if key not in schemas:
            # Not picked up by the schemas/ directory sweep above (missing file, or a ref
            # pointing outside schemas/ entirely) -- validate it directly so a bad reference
            # still fails the build.
            schema_path = manifest_dir / key
            if not schema_path.is_file():
                raise ManifestLabelError(f"{where}: schema file not found at {schema_path}")
            schemas[key] = _load_schema_object(schema_path, where)
    return schemas


def encode_schemas(schemas: dict[str, dict]) -> str:
    """Base64 (standard alphabet, padded) of the schemas map, compactly serialised with
    sorted keys so the same schemas always produce the same value. An empty map (no schemas/
    directory and no referenced schemas) -> empty string (no label content)."""
    if not schemas:
        return ""
    payload = json.dumps(schemas, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload).decode()


def compute_outputs(manifest_path: Path = MANIFEST_PATH) -> dict[str, str]:
    """The four key=value outputs this script prints, computed from the manifest at
    manifest_path. Raises ManifestLabelError if a referenced schema can't be resolved."""
    manifest_text = manifest_path.read_text()
    manifest = yaml.safe_load(manifest_text)
    manifest_b64 = base64.b64encode(manifest_text.encode()).decode()
    schemas = build_schemas_map(manifest, manifest_path.parent)
    return {
        "capability": manifest["capability"],
        "capability_version": manifest["version"],
        "manifest_b64": manifest_b64,
        "schemas_b64": encode_schemas(schemas),
    }


def main() -> int:
    try:
        outputs = compute_outputs(MANIFEST_PATH)
    except ManifestLabelError as exc:
        print(f"manifest_label: {exc}", file=sys.stderr)
        return 1

    for key, value in outputs.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
