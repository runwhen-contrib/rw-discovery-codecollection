"""The mechanics `export` and `logs` share: run one `kubectl` with the
request's `kubeconfig` credential and stream its stdout into the task's
`dump` artifact (`ctx.artifacts.from_process`), returning the task's output
mapping -- the artifact reference plus a small summary.

Same exec contract as `cli.run_cli()` -- a 0600 kubeconfig file in the
request's scope directory, deleted when the run ends however it ends, and a
child environment of exactly PATH, HOME and KUBECONFIG -- except that the
output is not capped or filtered here: it goes to the artifact, whole.
`from_process` merges an `env=` over the parent's environment rather than
replacing it, so the scrub is `env -i` in front of `kubectl`.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel
from runwhen_capability import Context

DUMP_ARTIFACT = "dump"  # the manifest's artifact output name

_STDERR_TAIL_BYTES = 4 * 1024
_DNS_LABEL_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")


def check_dns_label(value: str, what: str) -> str:
    """`value` if it is a DNS-1123 label (a namespace or container name),
    else a ValueError naming `what`."""
    if not _DNS_LABEL_RE.fullmatch(value):
        raise ValueError(f"{what} must be a DNS-1123 label (lower-case letters, digits and '-', at most 63): {value!r}")
    return value


@contextmanager
def kubeconfig_file(kubeconfig_yaml: str, workdir: Path) -> Iterator[str]:
    """The `kubeconfig` credential as a 0600 file inside `workdir` (same
    convention as `credentials.py.build_api_client`), yielded as a path and
    deleted again on the way out."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(dir=workdir, prefix=".kubeconfig-", suffix=".yaml")
    os.chmod(path, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(kubeconfig_yaml)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def scrubbed_env(kubeconfig_path: str) -> dict[str, str]:
    """The only environment `kubectl` ever sees."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "KUBECONFIG": kubeconfig_path,
    }


def _which(name: str, search_path: str) -> str:
    found = shutil.which(name, path=search_path)
    if found is None:
        raise FileNotFoundError(f"{name} not found on PATH")
    return found


def tail_utf8(text: str, max_bytes: int = _STDERR_TAIL_BYTES) -> str:
    """The last `max_bytes` of `text`'s UTF-8, never splitting a character."""
    return text.encode("utf-8")[-max_bytes:].decode("utf-8", errors="ignore")


def run_kubectl_to_artifact(
    ctx: Context,
    args: list[str],
    *,
    content_type: str,
    summary_model: type[BaseModel],
    kubectl_path: str = "kubectl",
) -> dict:
    """Streams `kubectl <args>` into artifact `dump`; returns
    `{"dump": <ArtifactRef>, "summary": <summary_model as a dict>}`.

    `args` is what follows `--kubeconfig <file>`; callers build it and have
    it checked against the pack's `cli` allow-list first. A non-zero exit
    does not raise -- the artifact is whatever `kubectl` wrote, and the
    summary reports its `returncode` and `stderrTail`. A timeout or an
    artifact error (the SDK's) propagates and fails the task.

    `kubectl_path` is a test seam (an injectable executable path); in
    production it is the bare `"kubectl"` name, resolved on PATH.
    """
    search_path = os.environ.get("PATH", "")
    env_bin = _which("env", search_path)
    kubectl_bin = _which(kubectl_path, search_path)
    with kubeconfig_file(ctx.credential("kubeconfig"), ctx.workdir) as kubeconfig:
        env = scrubbed_env(kubeconfig)
        argv = [
            env_bin,
            "-i",
            *(f"{name}={value}" for name, value in env.items()),
            kubectl_bin,
            "--kubeconfig",
            kubeconfig,
            *args,
        ]
        proc = ctx.artifacts.from_process(argv, DUMP_ARTIFACT, content_type=content_type)
    summary = summary_model(
        returncode=proc.returncode,
        bytes=proc.ref.size_bytes,
        stderrTail=tail_utf8(proc.stderr),
    )
    return {DUMP_ARTIFACT: proc.ref, "summary": summary.model_dump()}
