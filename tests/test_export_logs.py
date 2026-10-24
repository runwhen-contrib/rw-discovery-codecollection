"""Validates the `export` and `logs` tasks: a full `kubectl get -o json` or
`kubectl logs`, streamed into a `dump` artifact with a small summary beside it.

Everything runs for real except the cluster: a fake `kubectl` (a script this
file writes to `tmp_path` and points the task at, the same seam
`tests/test_cli.py` uses) is exec'd through the SDK's own
`ctx.artifacts.from_process`, in its local mode (no relay), so the artifact
is a real file under `<workdir>/.rw-artifacts/` and the argv, environment and
kubeconfig the fake sees are the ones a real `kubectl` would.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tracemalloc
from pathlib import Path

import pytest
from runwhen_capability import Context
from runwhen_capability.artifacts import ArtifactRef
from runwhen_capability.loader import load_capability

from rwdiscovery import cli
from rwdiscovery.export import build_export_argv, run_export
from rwdiscovery.logs import build_logs_argv, run_logs
from rwdiscovery.packbuild import load_pack_yaml
from tests.test_cli import KUBECONFIG_YAML, _received_argv, _write_fake_kubectl

CAPABILITY_DIR = Path(__file__).resolve().parent.parent / "capabilities" / "k8s-discovery"
CLI_BLOCK = load_pack_yaml()["cli"]

STDERR_TAIL_BYTES = 4096

# The fake dump: a header, N identical ~1 MB blocks, a footer. Deterministic,
# so the artifact's exact size and digest are known without reading the fake.
_HEADER = '{"items":['
_ITEM = '{"k":"' + "x" * 1000 + '"},'
_ITEMS_PER_BLOCK = 1000
_BLOCK = _ITEM * _ITEMS_PER_BLOCK
_FOOTER = "{}]}"


def _dump_size(blocks: int) -> int:
    return len(_HEADER) + blocks * len(_BLOCK) + len(_FOOTER)


def _write_dump_kubectl(tmp_path: Path, blocks: int, name: str = "fake-kubectl") -> Path:
    return _write_fake_kubectl(
        tmp_path,
        f"""
        import sys
        sys.stdout.write({_HEADER!r})
        for _ in range({blocks}):
            sys.stdout.write({_BLOCK!r})
        sys.stdout.write({_FOOTER!r})
        """,
        name=name,
    )


def _ctx(tmp_path: Path, operation: str = "export") -> Context:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return Context(
        capability="k8s-discovery",
        operation=operation,
        workdir=work,
        credentials={"kubeconfig": KUBECONFIG_YAML},
    )


def _dump_path(ctx: Context) -> Path:
    return ctx.workdir / ".rw-artifacts" / "dump"


def _exec_argv(tmp_path: Path) -> list[str]:
    """What the fake kubectl received after its `--kubeconfig <file>` pair."""
    received = _received_argv(tmp_path)
    assert received[0] == "--kubeconfig"
    assert Path(received[1]).name.startswith(".kubeconfig-")
    return received[2:]


# --- export: the dump artifact ------------------------------------------------


def test_export_streams_dump_artifact(tmp_path):
    blocks = 20  # ~20 MB
    script = _write_dump_kubectl(tmp_path, blocks)
    ctx = _ctx(tmp_path)

    result = run_export(ctx, resources="pods", namespace="prod", kubectl_path=str(script))

    expected = _HEADER + _BLOCK * blocks + _FOOTER
    assert len(expected) > 20_000_000
    dump = _dump_path(ctx)
    assert dump.stat().st_size == _dump_size(blocks)
    assert hashlib.sha256(dump.read_bytes()).hexdigest() == hashlib.sha256(expected.encode()).hexdigest()

    assert isinstance(result["dump"], ArtifactRef)  # the ref itself, not the ProcessArtifact around it
    assert result["dump"].ref.startswith("local_")
    assert result["dump"].model_dump() == {"$artifact": result["dump"].ref}
    assert result["summary"] == {"returncode": 0, "bytes": _dump_size(blocks), "stderrTail": ""}


# The SDK's writer holds about six 1 MiB chunks (four queued, one being sent,
# one being filled). Measured on this fake: a flat ~7.3 MiB traced peak from
# 20 MB to 64 MB of payload; 12 MiB leaves room for allocator noise while still
# being under a quarter of the payload, which a buffering `export` would blow.
PEAK_BOUND_BYTES = 12 * 1024 * 1024


def test_export_dump_stays_streamed_not_buffered(tmp_path):
    """The SDK queues a handful of 1 MiB chunks, nothing more: the traced
    peak must stay a small fraction of the payload, or `export` would hold a
    cluster's whole dump in memory."""
    blocks = 64  # ~64 MB
    script = _write_dump_kubectl(tmp_path, blocks)
    ctx = _ctx(tmp_path)

    tracemalloc.start()
    try:
        result = run_export(ctx, resources="all", kubectl_path=str(script))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result["summary"]["bytes"] == _dump_size(blocks)
    assert peak < PEAK_BOUND_BYTES, f"peak {peak} bytes"
    assert PEAK_BOUND_BYTES <= _dump_size(blocks) // 4


def test_export_all_namespaces_uses_dash_A(tmp_path):
    script = _write_dump_kubectl(tmp_path, 1)

    run_export(_ctx(tmp_path), resources="pods,services", kubectl_path=str(script))

    assert _exec_argv(tmp_path) == ["get", "pods,services", "--all-namespaces", "--output=json"]
    assert build_export_argv("pods", None, None) == ["get", "pods", "--all-namespaces", "--output=json"]


def test_export_defaults_to_all_resources_and_scopes_to_a_namespace_and_selector(tmp_path):
    script = _write_dump_kubectl(tmp_path, 1)

    run_export(_ctx(tmp_path), namespace="prod", selector="app=web,tier in (a,b)", kubectl_path=str(script))

    assert _exec_argv(tmp_path) == [
        "get",
        "all",
        "--namespace=prod",
        "--output=json",
        "--selector=app=web,tier in (a,b)",
    ]


@pytest.mark.parametrize(
    "resources",
    [
        "secrets",
        "secret",
        "Secrets",
        "SECRET",
        "secrets/db-creds",
        "secrets.v1",
        "secrets.v1.",
        "pods,secrets",
        "Secret,pods",
    ],
)
def test_export_rejects_secrets(tmp_path, resources):
    script = _write_dump_kubectl(tmp_path, 1)
    ctx = _ctx(tmp_path)

    with pytest.raises(ValueError, match="^secrets are never exported$"):
        build_export_argv(resources, "prod", None)
    with pytest.raises(ValueError, match="^secrets are never exported$"):
        run_export(ctx, resources=resources, namespace="prod", kubectl_path=str(script))

    assert not (tmp_path / "received-argv.json").exists()  # kubectl never ran
    assert not _dump_path(ctx).exists()


@pytest.mark.parametrize(
    "resources",
    [
        "-A",
        "--all-namespaces",
        "pods,-A",
        "",
        "pods services",
        "pods;ls",
        "$(id)",
        "pods\n",
        "pods,,services",
        "/pods",
    ],
)
def test_export_refuses_argv_injection_through_resources(resources):
    with pytest.raises(ValueError):
        build_export_argv(resources, None, None)


@pytest.mark.parametrize(
    "namespace", ["-A", "--all-namespaces", "Prod", "a b", "a;b", "x" * 64, "-prod", "prod-", "a.b"]
)
def test_export_refuses_a_namespace_that_is_not_a_dns_label(namespace):
    with pytest.raises(ValueError, match="namespace"):
        build_export_argv("pods", namespace, None)


def test_export_takes_a_selector_as_a_single_flag_token():
    """The value rides inside `--selector=...`, so a leading `-` can never be a flag of its own."""
    assert build_export_argv("pods", None, "-A") == [
        "get",
        "pods",
        "--all-namespaces",
        "--output=json",
        "--selector=-A",
    ]


def test_export_runs_the_pack_allow_list_over_what_it_builds():
    """A selector that is shell syntax is refused by `cli.validate`, with its reason."""
    with pytest.raises(ValueError, match="no-shell"):
        build_export_argv("pods", None, "app=web;")


def test_export_argv_is_always_accepted_by_the_pack_allow_list():
    argv = build_export_argv("pods,deployments.apps", "prod", "app=web")
    assert cli.validate(argv, CLI_BLOCK).ok


# --- logs ---------------------------------------------------------------------


def test_logs_builds_argv_with_since_and_selector():
    assert build_logs_argv(namespace="prod", selector="app=web", since="2h") == [
        "logs",
        "--namespace=prod",
        "--selector=app=web",
        "--all-containers",
        "--prefix",
        "--timestamps",
        "--since=2h",
        "--tail=-1",
        "--max-log-requests=20",
        "--ignore-errors",
    ]


def test_logs_builds_argv_for_a_workload_and_defaults_since_to_six_hours():
    assert build_logs_argv(namespace="prod", workload="deployment/web") == [
        "logs",
        "--namespace=prod",
        "deployment/web",
        "--all-containers",
        "--prefix",
        "--timestamps",
        "--since=6h",
        "--tail=-1",
        "--max-log-requests=20",
        "--ignore-errors",
    ]


def test_logs_container_replaces_all_containers():
    argv = build_logs_argv(namespace="prod", selector="app=web", container="sidecar")
    assert "--container=sidecar" in argv
    assert "--all-containers" not in argv


def test_logs_argv_is_always_accepted_by_the_pack_allow_list():
    for argv in (
        build_logs_argv(namespace="prod", selector="app=web", since="30m"),
        build_logs_argv(namespace="prod", workload="pod/web-0", container="app"),
    ):
        assert cli.validate(argv, CLI_BLOCK).ok


@pytest.mark.parametrize(
    "kwargs", [{}, {"selector": "app=web", "workload": "deployment/web"}, {"selector": "", "workload": ""}]
)
def test_logs_requires_selector_or_workload(kwargs):
    with pytest.raises(ValueError, match="selector or workload"):
        build_logs_argv(namespace="prod", **kwargs)


@pytest.mark.parametrize("namespace", [None, "", "-A", "Prod", "a b", "x" * 64])
def test_logs_requires_a_dns_label_namespace(namespace):
    with pytest.raises(ValueError, match="namespace"):
        build_logs_argv(namespace=namespace, selector="app=web")


@pytest.mark.parametrize("workload", ["-f", "--follow", "deployment/web;ls", "a b", "$(id)", "", "-deployment/web"])
def test_logs_refuses_argv_injection_through_workload(workload):
    with pytest.raises(ValueError):
        build_logs_argv(namespace="prod", workload=workload)


@pytest.mark.parametrize("since", ["6", "1d", "-1h", "6h; ls", "h", "1h30", "--follow", ""])
def test_logs_refuses_a_since_that_is_not_a_kubectl_duration(since):
    with pytest.raises(ValueError, match="since"):
        build_logs_argv(namespace="prod", selector="app=web", since=since)


@pytest.mark.parametrize("container", ["-p", "Sidecar", "a b", "x" * 64])
def test_logs_refuses_a_container_that_is_not_a_dns_label(container):
    with pytest.raises(ValueError, match="container"):
        build_logs_argv(namespace="prod", selector="app=web", container=container)


def test_logs_streams_text_to_a_dump_artifact(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        for i in range(1000):
            sys.stdout.write(f"[pod/web-0/app] 2026-01-01T00:00:00Z line {i}\\n")
        """,
    )
    ctx = _ctx(tmp_path, "logs")

    result = run_logs(ctx, namespace="prod", selector="app=web", kubectl_path=str(script))

    lines = _dump_path(ctx).read_text().splitlines()
    assert len(lines) == 1000
    assert lines[-1].endswith("line 999")
    assert result["summary"] == {"returncode": 0, "bytes": _dump_path(ctx).stat().st_size, "stderrTail": ""}
    assert _exec_argv(tmp_path) == build_logs_argv(namespace="prod", selector="app=web")


# --- a failing kubectl --------------------------------------------------------


def test_nonzero_exit_reports_stderr_tail(tmp_path):
    """Non-zero exit does not fail the task: the partial dump is kept and the
    summary carries the exit code and the LAST 4 KiB of stderr."""
    error_line = "Error from server (Forbidden): pods is forbidden"
    script = _write_fake_kubectl(
        tmp_path,
        f"""
        import sys
        sys.stdout.write({_HEADER!r})
        sys.stderr.write({"A" * 6000!r} + {error_line!r})
        sys.exit(3)
        """,
    )
    ctx = _ctx(tmp_path)

    result = run_export(ctx, resources="pods", namespace="prod", kubectl_path=str(script))

    summary = result["summary"]
    assert summary["returncode"] == 3
    assert summary["bytes"] == len(_HEADER) == _dump_path(ctx).stat().st_size
    assert summary["stderrTail"] == "A" * (STDERR_TAIL_BYTES - len(error_line)) + error_line


def test_stderr_tail_is_cut_on_a_utf8_boundary(tmp_path):
    # 2-byte characters: an odd cut would land mid-character.
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        sys.stderr.buffer.write(("é" * 3000).encode("utf-8"))
        sys.exit(1)
        """,
    )

    result = run_logs(_ctx(tmp_path, "logs"), namespace="prod", selector="app=web", kubectl_path=str(script))

    tail = result["summary"]["stderrTail"]
    assert "\N{REPLACEMENT CHARACTER}" not in tail
    assert set(tail) == {"é"}
    assert len(tail.encode()) == STDERR_TAIL_BYTES  # 4096 is even: whole characters fit exactly


def test_summaries_carry_exactly_the_fields_their_published_schemas_declare(tmp_path):
    script = _write_fake_kubectl(tmp_path, "import sys; sys.stdout.write('ok')")
    schemas = CAPABILITY_DIR / "schemas"

    exported = run_export(_ctx(tmp_path), resources="pods", kubectl_path=str(script))["summary"]
    logged = run_logs(_ctx(tmp_path, "logs"), namespace="prod", selector="app=web", kubectl_path=str(script))["summary"]

    for summary, filename in ((exported, "k8s_export_summary.v1.json"), (logged, "k8s_logs_summary.v1.json")):
        schema = json.loads((schemas / filename).read_text())
        assert set(summary) == set(schema["properties"]) == set(schema["required"])


def test_short_stderr_is_reported_whole(tmp_path):
    script = _write_fake_kubectl(tmp_path, "import sys; sys.stderr.write('boom'); sys.exit(1)")

    result = run_export(_ctx(tmp_path), resources="pods", kubectl_path=str(script))

    assert result["summary"]["stderrTail"] == "boom"


# --- how kubectl is exec'd ----------------------------------------------------


def test_kubectl_gets_only_path_home_and_kubeconfig(tmp_path, monkeypatch):
    """A plain `/bin/sh` fake, as in test_cli: an interpreter adds a few
    bookkeeping vars of its own (`PWD`/`SHLVL`/`_`) whatever a parent passes
    it. The point is that nothing from the *parent's* environment beyond
    PATH/HOME/KUBECONFIG reaches the child -- `from_process` merges env over
    the parent's, so the scrub is an `env -i` in front of kubectl."""
    monkeypatch.setenv("RWDISCOVERY_TEST_SECRET", "leak-me")
    script = tmp_path / "fake-kubectl"
    script.write_text("#!/bin/sh\nenv\n")
    script.chmod(0o755)
    ctx = _ctx(tmp_path)

    run_export(ctx, resources="pods", kubectl_path=str(script))

    dump = _dump_path(ctx).read_text()
    seen = {line.split("=", 1)[0] for line in dump.splitlines() if "=" in line}
    assert {"PATH", "HOME", "KUBECONFIG"} <= seen
    assert seen <= {"PATH", "HOME", "KUBECONFIG", "PWD", "SHLVL", "_"}
    assert "RWDISCOVERY_TEST_SECRET" not in dump
    assert "leak-me" not in dump
    assert f"PATH={os.environ['PATH']}" in dump
    assert f"HOME={os.environ.get('HOME', '')}" in dump


def test_kubeconfig_is_0600_during_the_run_and_removed_after(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import os, stat, sys
        argv = sys.argv[1:]
        path = argv[argv.index("--kubeconfig") + 1]
        assert os.environ["KUBECONFIG"] == path
        sys.stdout.write(f"MODE:{oct(stat.S_IMODE(os.stat(path).st_mode))}\\n")
        sys.stdout.write(open(path).read())
        """,
    )
    ctx = _ctx(tmp_path)

    run_logs(ctx, namespace="prod", selector="app=web", kubectl_path=str(script))

    dump = _dump_path(ctx).read_text()
    assert dump == f"MODE:{oct(0o600)}\n{KUBECONFIG_YAML}"
    assert not list(ctx.workdir.glob(".kubeconfig-*"))
    assert Path(_received_argv(tmp_path)[1]).parent == ctx.workdir


def test_kubeconfig_is_removed_when_the_run_fails_to_finish(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.deadline_at = 0.0  # already past: from_process raises before starting a child
    script = _write_dump_kubectl(tmp_path, 1)

    with pytest.raises(subprocess.TimeoutExpired):
        run_export(ctx, resources="pods", kubectl_path=str(script))

    assert not list(ctx.workdir.glob(".kubeconfig-*"))


def test_no_request_timeout_flag_is_passed(tmp_path):
    """The request's own deadline bounds the run, not a kubectl `--request-timeout`."""
    script = _write_dump_kubectl(tmp_path, 1)

    run_export(_ctx(tmp_path), resources="pods", kubectl_path=str(script))

    assert not any(arg.startswith("--request-timeout") for arg in _received_argv(tmp_path))


def test_a_missing_kubectl_fails_clearly_and_leaves_no_kubeconfig(tmp_path):
    ctx = _ctx(tmp_path)

    with pytest.raises(FileNotFoundError, match="kubectl"):
        run_export(ctx, resources="pods", kubectl_path=str(tmp_path / "no-such-kubectl"))

    assert not list(ctx.workdir.glob(".kubeconfig-*"))


def test_a_missing_env_binary_fails_clearly(tmp_path, monkeypatch):
    script = _write_dump_kubectl(tmp_path, 1)
    monkeypatch.setenv("PATH", "")

    with pytest.raises(FileNotFoundError, match="^env not found"):
        run_logs(_ctx(tmp_path, "logs"), namespace="prod", selector="app=web", kubectl_path=str(script))


# --- the tasks, through the capability registry -------------------------------


def _kubectl_on_path(tmp_path: Path, monkeypatch, blocks: int) -> None:
    """A fake dump `kubectl`, found by the bare name `kubectl` as in production."""
    _write_dump_kubectl(tmp_path, blocks, name="kubectl")
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")


def test_export_task_returns_the_artifact_ref_and_summary(tmp_path, monkeypatch):
    _kubectl_on_path(tmp_path, monkeypatch, 2)
    ctx = _ctx(tmp_path)

    export = load_capability(CAPABILITY_DIR).registry.tasks["export"].func
    result = export(ctx, cluster_name="c1", namespace="prod")

    assert set(result) == {"dump", "summary"}
    assert result["dump"].model_dump() == {"$artifact": result["dump"].ref}
    assert result["summary"]["bytes"] == _dump_size(2)
    assert _exec_argv(tmp_path) == ["get", "all", "--namespace=prod", "--output=json"]


def test_logs_task_returns_the_artifact_ref_and_summary(tmp_path, monkeypatch):
    _kubectl_on_path(tmp_path, monkeypatch, 1)
    ctx = _ctx(tmp_path, "logs")

    logs = load_capability(CAPABILITY_DIR).registry.tasks["logs"].func
    result = logs(ctx, cluster_name="c1", namespace="prod", workload="deployment/web", since="1h", container="app")

    assert set(result) == {"dump", "summary"}
    assert result["summary"]["returncode"] == 0
    assert _exec_argv(tmp_path) == build_logs_argv(
        namespace="prod", workload="deployment/web", since="1h", container="app"
    )


def test_tasks_treat_a_null_default_input_as_unset(tmp_path, monkeypatch):
    """The platform may send an explicit null for an optional input it was not given."""
    _kubectl_on_path(tmp_path, monkeypatch, 1)
    tasks = load_capability(CAPABILITY_DIR).registry.tasks

    tasks["export"].func(_ctx(tmp_path), cluster_name="c1", resources=None, namespace=None, selector=None)
    assert _exec_argv(tmp_path) == ["get", "all", "--all-namespaces", "--output=json"]

    tasks["logs"].func(_ctx(tmp_path, "logs"), cluster_name="c1", namespace="prod", selector="app=web", since=None)
    assert "--since=6h" in _exec_argv(tmp_path)
