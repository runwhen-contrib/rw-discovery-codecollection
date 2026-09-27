#!/usr/bin/env python3
"""Reads capabilities/k8s-discovery/manifest.yaml and prints the values the
Dockerfile bakes in as OCI labels, so the labels can never drift from the
manifest they describe -- the image itself carries its own manifest (and the
JSON Schemas its task outputs reference) as OCI labels, so the catalog can
read them straight off the pushed image.

Besides the manifest bytes, this also collects every `tasks[*].outputs.
<name>.schema` reference in the manifest (e.g. `./schemas/k8s_object.json`),
resolves it relative to the manifest's own directory, and bundles the parsed
schemas into one JSON object -- keyed by the reference normalised with
posixpath.normpath -- that becomes the com.runwhen.capability.schemas.v1
label. A capability whose manifest references no schema gets an empty value
(no label content, but the key is still printed). A referenced schema that
is missing, not valid JSON, not a JSON object, or whose path escapes the
manifest's directory fails the build rather than shipping a silently
incomplete label.

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


def build_schemas_map(manifest: dict, manifest_dir: Path) -> dict[str, dict]:
    """Resolve every tasks[*].outputs[*].schema reference into {normalised_key: parsed_schema}.

    Raises ManifestLabelError, naming the offending task/output/path, when a reference is
    absolute, escapes manifest_dir via a '..' segment, the file is missing, is not valid
    JSON, or is not a JSON object.
    """
    schemas: dict[str, dict] = {}
    for task_name, output_name, schema_ref in collect_schema_refs(manifest):
        where = f"task {task_name!r} output {output_name!r} (schema: {schema_ref!r})"
        key = posixpath.normpath(schema_ref)
        if posixpath.isabs(key) or key == ".." or key.startswith("../"):
            raise ManifestLabelError(
                f"{where}: schema path must be relative and stay under the manifest's own directory"
            )
        schema_path = manifest_dir / key
        if not schema_path.is_file():
            raise ManifestLabelError(f"{where}: schema file not found at {schema_path}")
        try:
            parsed = json.loads(schema_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ManifestLabelError(f"{where}: schema file {schema_path} is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ManifestLabelError(
                f"{where}: schema file {schema_path} must be a JSON object, got {type(parsed).__name__}"
            )
        schemas[key] = parsed
    return schemas


def encode_schemas(schemas: dict[str, dict]) -> str:
    """Base64 (standard alphabet, padded) of the schemas map, compactly serialised with
    sorted keys so the same schemas always produce the same value. No referenced schemas
    -> empty string (no label content)."""
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
