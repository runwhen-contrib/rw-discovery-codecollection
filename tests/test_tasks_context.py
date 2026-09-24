"""`capabilities/k8s-discovery/tasks.py`'s `discover`/`inspect` forward an
optional `context` input straight through to `rwdiscovery`'s own
`run_discover`/`run_inspect` -- this is the only thing `tasks.py` itself is
responsible for; the actual kubeconfig-context selection is covered end to
end in `test_credentials.py` and at the `run_discover`/`run_inspect`
boundary in `test_discover_e2e.py`/`test_inspect.py`.
"""

from __future__ import annotations

from pathlib import Path

from runwhen_capability import Context
from runwhen_capability.loader import load_capability

import rwdiscovery.discover as discover_lib
import rwdiscovery.inspect as inspect_lib

CAPABILITY_DIR = Path(__file__).resolve().parent.parent / "capabilities" / "k8s-discovery"


def _context(tmp_path: Path) -> Context:
    return Context(
        capability="k8s-discovery",
        operation="test",
        workdir=tmp_path,
        credentials={"kubeconfig": "unused", "resourceSync": "{}"},
    )


def test_discover_task_forwards_context_input_to_run_discover(tmp_path: Path, monkeypatch):
    captured: dict = {}

    def _fake_run_discover(**kwargs):
        captured.update(kwargs)
        return {"stub": True}

    monkeypatch.setattr(discover_lib, "run_discover", _fake_run_discover)

    discover = load_capability(CAPABILITY_DIR).registry.tasks["discover"].func
    discover(_context(tmp_path), cluster_name="c1", context="ctx-two")

    assert captured["context"] == "ctx-two"


def test_discover_task_context_defaults_to_none(tmp_path: Path, monkeypatch):
    captured: dict = {}

    def _fake_run_discover(**kwargs):
        captured.update(kwargs)
        return {"stub": True}

    monkeypatch.setattr(discover_lib, "run_discover", _fake_run_discover)

    discover = load_capability(CAPABILITY_DIR).registry.tasks["discover"].func
    discover(_context(tmp_path), cluster_name="c1")

    assert captured["context"] is None


def test_inspect_task_forwards_context_input_to_run_inspect(tmp_path: Path, monkeypatch):
    captured: dict = {}

    def _fake_run_inspect(**kwargs):
        captured.update(kwargs)
        return {"stub": True}

    monkeypatch.setattr(inspect_lib, "run_inspect", _fake_run_inspect)

    inspect = load_capability(CAPABILITY_DIR).registry.tasks["inspect"].func
    inspect(_context(tmp_path), cluster_name="c1", kind="Pod", name="n", mode="get", context="ctx-two")

    assert captured["context"] == "ctx-two"


def test_inspect_task_context_defaults_to_none(tmp_path: Path, monkeypatch):
    captured: dict = {}

    def _fake_run_inspect(**kwargs):
        captured.update(kwargs)
        return {"stub": True}

    monkeypatch.setattr(inspect_lib, "run_inspect", _fake_run_inspect)

    inspect = load_capability(CAPABILITY_DIR).registry.tasks["inspect"].func
    inspect(_context(tmp_path), cluster_name="c1", kind="Pod", name="n", mode="get")

    assert captured["context"] is None
