"""Unit-level coverage for scripts/manifest_label.py's output-schema
collection -- the com.runwhen.capability.schemas.v1 label. Mirrors
tests/test_schemas.py's `sys.path.insert` trick to import the script as a
module. tests/test_manifest.py covers the real, checked-in manifest end to
end, through the script's CLI; this file exercises the failure paths
(missing/invalid schema, an escaping path, no schemas at all) and the
"every file in schemas/, not only the referenced ones" behaviour that the
real manifest never hits (it has no unreferenced, older schema version yet).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPABILITY_DIR = REPO_ROOT / "capabilities" / "k8s-discovery"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from manifest_label import (  # noqa: E402
    ManifestLabelError,
    build_schemas_map,
    compute_outputs,
    encode_schemas,
)


def _manifest(schema_ref: str | None) -> dict:
    output = {"schema": schema_ref} if schema_ref else {}
    return {"tasks": [{"name": "atask", "outputs": {"anoutput": output}}]}


# ---------------------------------------------------------------------------
# the real, checked-in manifest
# ---------------------------------------------------------------------------
def test_real_manifest_schemas_label_has_exactly_the_three_published_schemas():
    # Today schemas/ holds exactly the three versions the manifest references (v1 of each) --
    # once a schema is versioned past v1, this label grows to carry the older version too; see
    # test_schemas_map_includes_every_file_in_schemas_dir_not_only_referenced below.
    outputs = compute_outputs()
    decoded = json.loads(base64.b64decode(outputs["schemas_b64"]))
    assert decoded.keys() == {
        "schemas/discovery_summary.v1.json",
        "schemas/k8s_object.v1.json",
        "schemas/cli_result.v1.json",
    }
    for filename, key in (
        ("discovery_summary.v1.json", "schemas/discovery_summary.v1.json"),
        ("k8s_object.v1.json", "schemas/k8s_object.v1.json"),
        ("cli_result.v1.json", "schemas/cli_result.v1.json"),
    ):
        expected = json.loads((CAPABILITY_DIR / "schemas" / filename).read_text())
        assert decoded[key] == expected


def test_real_manifest_schemas_label_is_deterministic():
    first = compute_outputs()["schemas_b64"]
    second = compute_outputs()["schemas_b64"]
    assert first == second


# ---------------------------------------------------------------------------
# failure paths
# ---------------------------------------------------------------------------
def test_missing_schema_file_fails(tmp_path: Path):
    manifest = _manifest("./schemas/missing.json")
    with pytest.raises(ManifestLabelError, match="not found"):
        build_schemas_map(manifest, tmp_path)


def test_dotdot_schema_path_fails(tmp_path: Path):
    (tmp_path / "escape.json").write_text("{}")
    manifest = _manifest("../escape.json")
    with pytest.raises(ManifestLabelError, match="relative"):
        build_schemas_map(manifest, tmp_path)


def test_absolute_schema_path_fails(tmp_path: Path):
    manifest = _manifest("/etc/passwd")
    with pytest.raises(ManifestLabelError, match="relative"):
        build_schemas_map(manifest, tmp_path)


def test_invalid_json_schema_fails(tmp_path: Path):
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir()
    (schemas_dir / "bad.json").write_text("{not valid json")
    manifest = _manifest("./schemas/bad.json")
    with pytest.raises(ManifestLabelError, match="not valid JSON"):
        build_schemas_map(manifest, tmp_path)


def test_non_object_json_schema_fails(tmp_path: Path):
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir()
    (schemas_dir / "array.json").write_text("[1, 2, 3]")
    manifest = _manifest("./schemas/array.json")
    with pytest.raises(ManifestLabelError, match="JSON object"):
        build_schemas_map(manifest, tmp_path)


# ---------------------------------------------------------------------------
# no schemas referenced
# ---------------------------------------------------------------------------
def test_manifest_with_no_schema_refs_gives_an_empty_schemas_map(tmp_path: Path):
    manifest = _manifest(None)
    assert build_schemas_map(manifest, tmp_path) == {}


def test_empty_schemas_map_encodes_to_the_empty_string():
    assert encode_schemas({}) == ""


# ---------------------------------------------------------------------------
# the label carries every published version, not only the referenced one
# ---------------------------------------------------------------------------
def test_schemas_map_includes_every_file_in_schemas_dir_not_only_referenced(tmp_path: Path):
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir()
    (schemas_dir / "athing.v1.json").write_text('{"v": 1}')
    (schemas_dir / "athing.v2.json").write_text('{"v": 2}')
    manifest = _manifest("./schemas/athing.v2.json")

    schemas = build_schemas_map(manifest, tmp_path)

    assert schemas.keys() == {"schemas/athing.v1.json", "schemas/athing.v2.json"}
    assert schemas["schemas/athing.v1.json"] == {"v": 1}
    assert schemas["schemas/athing.v2.json"] == {"v": 2}


def test_unreferenced_invalid_schema_in_the_directory_still_fails_the_build(tmp_path: Path):
    # Every file in schemas/ is validated, not only the ones a task references -- an unreferenced
    # but broken file would otherwise ship silently in the label.
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir()
    (schemas_dir / "athing.v1.json").write_text("{not valid json")
    manifest = _manifest(None)
    with pytest.raises(ManifestLabelError, match="not valid JSON"):
        build_schemas_map(manifest, tmp_path)
