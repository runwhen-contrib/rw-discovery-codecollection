"""Sanity-checks the shipped capability manifest -- mirrors rw-checks-
codecollection's tests/test_manifest.py.

Also covers the capability release model (rw-checks-codecollection#6,
codecollection-registry#189): the manifest has no `image` key -- an image
cannot know its own digest -- and `Dockerfile.k8s-discovery` labels the
built image with `com.runwhen.capability.manifest.v1`, the exact OCI label
`cc-catalog-svc/app/sources/capability.py`'s `CAPABILITY_MANIFEST_LABEL`
reads back off the pushed image."""

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

from runwhen_capability.loader import load_capability, load_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPABILITY_DIR = REPO_ROOT / "capabilities" / "k8s-discovery"
DOCKERFILE = REPO_ROOT / "Dockerfile.k8s-discovery"
MANIFEST_LABEL_SCRIPT = REPO_ROOT / "scripts" / "manifest_label.py"

# The exact label codecollection-registry#189's cc-catalog-svc/app/sources/
# capability.py reads (`CAPABILITY_MANIFEST_LABEL`). Any drift here between
# what the Dockerfile writes and what the catalog reads means the catalog
# silently never discovers this capability -- see
# test_dockerfile_label_key_matches_the_catalog_reader below.
CAPABILITY_MANIFEST_LABEL = "com.runwhen.capability.manifest.v1"

REQUIRED_KEYS = {
    "apiVersion",
    "capability",
    "version",
    "description",
    "execution",
    "appliesTo",
    "needs",
    "setup",
    "tasks",
    "retention",
}


def test_manifest_has_required_top_level_keys():
    manifest = load_manifest(CAPABILITY_DIR)
    missing = REQUIRED_KEYS - manifest.keys()
    assert not missing, missing


def test_manifest_has_no_image_key():
    # An image cannot know its own digest -- the registry/catalog own it
    # now. The manifest rides the image itself, as the
    # com.runwhen.capability.manifest.v1 label (see the Dockerfile tests
    # below).
    manifest = load_manifest(CAPABILITY_DIR)
    assert "image" not in manifest


def test_manifest_capability_id_and_execution_mode():
    manifest = load_manifest(CAPABILITY_DIR)
    assert manifest["capability"] == "k8s-discovery"
    assert manifest["execution"]["mode"] == "stateless"


def test_manifest_execution_resources_and_work_size_limit():
    manifest = load_manifest(CAPABILITY_DIR)
    resources = manifest["execution"]["resources"]
    assert resources.keys() == {"cpuRequest", "cpuLimit", "memoryRequest", "memoryLimit"}
    assert all(isinstance(v, str) for v in resources.values())
    assert isinstance(manifest["execution"]["workSizeLimit"], str)


def test_manifest_declares_optional_context_input_for_discover_and_inspect():
    manifest = load_manifest(CAPABILITY_DIR)
    by_name = {t["name"]: t for t in manifest["tasks"]}
    for name in ("discover", "inspect"):
        context_input = by_name[name]["inputs"]["context"]
        assert context_input["from"] == "request"
        assert context_input["optional"] is True


def test_manifest_declares_both_credentials():
    manifest = load_manifest(CAPABILITY_DIR)
    names_and_kinds = {c["name"]: c["kind"] for c in manifest["needs"]["credentials"]}
    assert names_and_kinds == {"kubeconfig": "k8s.kubeconfig", "resourceSync": "runwhen.resourceSync"}


def test_manifest_declares_readonly_flags_per_capability_contract():
    manifest = load_manifest(CAPABILITY_DIR)
    by_name = {t["name"]: t for t in manifest["tasks"]}
    assert by_name["discover"]["readOnly"] is False
    assert by_name["inspect"]["readOnly"] is True


def test_capability_loads_and_registers_setup_and_tasks():
    loaded = load_capability(CAPABILITY_DIR)
    assert loaded.capability_id == "k8s-discovery"
    assert "connect" in loaded.registry.setups
    assert {"discover", "inspect"} <= loaded.registry.tasks.keys()


# The platform's executor host calls each function as `func(ctx, **inputs)`
# with the request's camelCase input names converted to snake_case, and the
# platform only ever sends inputs the manifest declares. A declared input
# the function does not accept is a TypeError on every run; a required
# parameter the manifest does not declare can never be supplied.
_KNOWN_EXECUTION_KEYS = {
    "mode",
    "maxPodsPerPool",
    "maxConcurrentPerPod",
    "idleTtlSeconds",
    "requestTimeoutSeconds",
    "resources",
    "workSizeLimit",
}


def _snake(name: str) -> str:
    return "".join(f"_{c.lower()}" if c.isupper() else c for c in name)


def _params(func) -> tuple[set[str], set[str]]:
    import inspect  # noqa: PLC0415 -- stdlib, test-local

    params = list(inspect.signature(func).parameters.values())[1:]  # drop ctx
    required = {p.name for p in params if p.default is inspect.Parameter.empty}
    return {p.name for p in params}, required


def test_manifest_inputs_match_the_function_signatures():
    manifest = load_manifest(CAPABILITY_DIR)
    loaded = load_capability(CAPABILITY_DIR)
    entries = [(manifest["setup"], loaded.registry.setups[manifest["setup"]["task"]].func)]
    entries += [(t, loaded.registry.tasks[t["name"]].func) for t in manifest["tasks"]]
    for spec, func in entries:
        declared = {_snake(k): v for k, v in (spec.get("inputs") or {}).items()}
        accepted, required = _params(func)
        assert set(declared) <= accepted, (func.__name__, set(declared) - accepted)
        declared_required = {k for k, v in declared.items() if not v.get("optional")}
        assert required <= declared_required, (func.__name__, required - declared_required)


def test_manifest_execution_uses_only_fields_the_platform_understands():
    manifest = load_manifest(CAPABILITY_DIR)
    assert set(manifest["execution"]) <= _KNOWN_EXECUTION_KEYS, set(manifest["execution"]) - _KNOWN_EXECUTION_KEYS


# ---------------------------------------------------------------------------
# release model: the manifest label the Dockerfile writes and the catalog
# reads (codecollection-registry#189's cc-catalog-svc/app/sources/
# capability.py), and scripts/manifest_label.py, which computes it.
# ---------------------------------------------------------------------------
def test_dockerfile_label_key_matches_the_catalog_reader():
    dockerfile_text = DOCKERFILE.read_text()
    assert f'{CAPABILITY_MANIFEST_LABEL}="${{MANIFEST_B64}}"' in dockerfile_text
    # The old, pre-release-model label name must not linger alongside it.
    assert "io.runwhen.capability.manifest=" not in dockerfile_text


def _run_manifest_label_script() -> dict[str, str]:
    result = subprocess.run(
        [sys.executable, str(MANIFEST_LABEL_SCRIPT)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if line)


def test_manifest_label_script_round_trips_the_manifest_bytes():
    outputs = _run_manifest_label_script()
    manifest_bytes = (CAPABILITY_DIR / "manifest.yaml").read_bytes()
    assert base64.b64decode(outputs["manifest_b64"]) == manifest_bytes


def test_manifest_label_script_reports_capability_and_version():
    outputs = _run_manifest_label_script()
    manifest = load_manifest(CAPABILITY_DIR)
    assert outputs["capability"] == manifest["capability"]
    assert outputs["capability_version"] == manifest["version"]
