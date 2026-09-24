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
