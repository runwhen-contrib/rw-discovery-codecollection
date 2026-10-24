"""The `logs` task: a full `kubectl logs` for a selector's pods or one
workload, streamed into a `dump` artifact. Where `cli` returns a small,
capped slice of kubectl's output inline, this keeps all of it.

Like `export`, the request's values only ever reach kubectl inside
`--flag=value` tokens or as the one strictly-checked positional, and the argv
`build_logs_argv()` composes is checked against the `cli` allow-list.
"""

from __future__ import annotations

import re

from runwhen_capability import Context

from . import cli
from .kubectl_artifact import check_dns_label, run_kubectl_to_artifact
from .models import K8sLogsSummary

DEFAULT_SINCE = "6h"

# `deployment/web`, `pod/web-0`, `web-0`: no part can read as a flag.
_WORKLOAD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./-]*")
# kubectl's own duration syntax, narrowed to what `--since` takes: 90s, 2h, 1h30m.
_SINCE_RE = re.compile(r"([0-9]+[hms])+")


def build_logs_argv(
    namespace: str | None,
    selector: str | None = None,
    workload: str | None = None,
    container: str | None = None,
    since: str = DEFAULT_SINCE,
) -> list[str]:
    """`logs --namespace=<ns> (--selector=<sel> | <workload>)
    (--all-containers | --container=<c>) --prefix --timestamps
    --since=<since> --tail=-1 --max-log-requests=20 --ignore-errors`.

    Exactly one of `selector` and `workload` is required (empty counts as
    absent). `--tail=-1` is explicit because kubectl otherwise shows only the
    last 10 lines per container whenever a selector is given."""
    if not namespace:
        raise ValueError("namespace is required")
    check_dns_label(namespace, "namespace")
    if bool(selector) == bool(workload):
        raise ValueError("pass exactly one of selector or workload")
    if not _SINCE_RE.fullmatch(since):
        raise ValueError(f"since must be a duration such as 90s, 2h or 1h30m, got {since!r}")

    argv = ["logs", f"--namespace={namespace}"]
    if selector:
        argv.append(f"--selector={selector}")
    else:
        if not _WORKLOAD_RE.fullmatch(workload):
            raise ValueError(f"workload must look like deployment/web or a pod name, got {workload!r}")
        argv.append(workload)
    # kubectl refuses --container together with --all-containers.
    argv.append(f"--container={check_dns_label(container, 'container')}" if container else "--all-containers")
    argv += ["--prefix", "--timestamps", f"--since={since}", "--tail=-1", "--max-log-requests=20", "--ignore-errors"]
    cli.require_allowed(argv)
    return argv


def run_logs(
    ctx: Context,
    namespace: str | None,
    selector: str | None = None,
    workload: str | None = None,
    since: str | None = None,
    container: str | None = None,
    *,
    kubectl_path: str = "kubectl",
) -> dict:
    """The `logs` task's outputs: `{"dump": <ArtifactRef>, "summary":
    {returncode, bytes, stderrTail}}`."""
    argv = build_logs_argv(namespace, selector, workload, container, since or DEFAULT_SINCE)
    return run_kubectl_to_artifact(
        ctx,
        argv,
        content_type="text/plain",
        summary_model=K8sLogsSummary,
        kubectl_path=kubectl_path,
    )
