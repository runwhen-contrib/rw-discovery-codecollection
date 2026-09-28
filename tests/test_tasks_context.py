"""`capabilities/k8s-discovery/tasks.py`'s `connect`/`discover` forward an
optional `context` input straight through to `rwdiscovery`'s own
`connect`/`run_discover` -- this is the only thing `tasks.py` itself is
responsible for; the actual kubeconfig-context selection is covered end to
end in `test_credentials.py` and at the `run_discover` boundary in
`test_discover_e2e.py`. `cli` (platform-contract §7, the read path `inspect`
was retired in favour of) takes no `context` input of its own -- it always
runs against the kubeconfig's current-context, same as a bare `kubectl`.
"""

from __future__ import annotations

from pathlib import Path

from runwhen_capability import Context
from runwhen_capability.loader import load_capability

import rwdiscovery.connect as connect_lib
import rwdiscovery.discover as discover_lib

CAPABILITY_DIR = Path(__file__).resolve().parent.parent / "capabilities" / "k8s-discovery"


def _context(tmp_path: Path) -> Context:
    return Context(
        capability="k8s-discovery",
        operation="test",
        workdir=tmp_path,
        credentials={"kubeconfig": "unused", "resourceSync": "{}"},
    )


def test_connect_setup_forwards_context_input_to_connect_lib(tmp_path: Path, monkeypatch):
    """LOW: `connect`'s reachability precheck must cover the same context a
    scheduled `discover` run is configured with, not just the kubeconfig's
    default current-context."""
    captured: dict = {}

    def _fake_connect(kubeconfig_yaml, workdir, context=None):
        captured["context"] = context
        return {"serverVersion": "", "clusterUid": ""}

    monkeypatch.setattr(connect_lib, "connect", _fake_connect)

    connect = load_capability(CAPABILITY_DIR).registry.setups["connect"].func
    connect(_context(tmp_path), context="ctx-two")

    assert captured["context"] == "ctx-two"


def test_connect_setup_context_defaults_to_none(tmp_path: Path, monkeypatch):
    captured: dict = {}

    def _fake_connect(kubeconfig_yaml, workdir, context=None):
        captured["context"] = context
        return {"serverVersion": "", "clusterUid": ""}

    monkeypatch.setattr(connect_lib, "connect", _fake_connect)

    connect = load_capability(CAPABILITY_DIR).registry.setups["connect"].func
    connect(_context(tmp_path))

    assert captured["context"] is None


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
