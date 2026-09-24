"""Sanity-checks the shipped capability manifest -- mirrors rw-checks-
codecollection's tests/test_manifest.py."""

from __future__ import annotations

from pathlib import Path

from runwhen_capability.loader import load_capability, load_manifest

CAPABILITY_DIR = Path(__file__).resolve().parent.parent / "capabilities" / "k8s-discovery"

REQUIRED_KEYS = {
    "apiVersion",
    "capability",
    "version",
    "description",
    "image",
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


def test_manifest_capability_id_and_execution_mode():
    manifest = load_manifest(CAPABILITY_DIR)
    assert manifest["capability"] == "k8s-discovery"
    assert manifest["execution"]["mode"] == "stateless"


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
