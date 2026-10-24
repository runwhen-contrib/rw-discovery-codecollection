"""The `export` task: a full `kubectl get <resources> -o json`, streamed into
a `dump` artifact. Where `cli` returns a small, capped slice of kubectl's
output inline, this keeps all of it -- a cluster's worth, if asked.

Secrets are never exported. The request's values only ever reach kubectl as
argv tokens `build_export_argv()` composes (flag values inside `--flag=value`,
the one positional held to a strict charset), and what it builds is checked
against the same `cli` allow-list the `cli` task enforces.
"""

from __future__ import annotations

import re

from runwhen_capability import Context

from . import cli, packbuild
from .kubectl_artifact import check_dns_label, run_kubectl_to_artifact
from .models import K8sExportSummary

DEFAULT_RESOURCES = "all"

# What is never exported, whatever the pack's own `sensitiveTypes` says.
_NEVER_EXPORTED = frozenset({"secret", "secrets"})

# `pods,deployments.apps,pod/web-0`: comma-separated, each part starting with
# a letter or digit so no part can read as a flag.
_RESOURCES_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./-]*(,[A-Za-z0-9][A-Za-z0-9./-]*)*")


def build_export_argv(resources: str, namespace: str | None, selector: str | None) -> list[str]:
    """`get <resources> (--namespace=<ns> | --all-namespaces) --output=json
    [--selector=<sel>]`, after refusing Secrets and anything that is not a
    plain resource list. An omitted (None) `namespace` means all namespaces;
    an empty one is refused."""
    cli_block = packbuild.load_pack_yaml()["cli"]
    sensitive = _NEVER_EXPORTED | {t.lower() for t in cli_block.get("sensitiveTypes") or []}
    if any(cli.resource_type(part.strip()) in sensitive for part in resources.split(",")):
        raise ValueError("secrets are never exported")
    if not _RESOURCES_RE.fullmatch(resources):
        raise ValueError(f"resources must be a comma-separated list of resource types, got {resources!r}")

    argv = ["get", resources]
    if namespace is None:
        argv.append("--all-namespaces")
    else:
        argv.append(f"--namespace={check_dns_label(namespace, 'namespace')}")
    argv.append("--output=json")
    if selector:
        argv.append(f"--selector={selector}")
    cli.require_allowed(argv, cli_block)
    return argv


def run_export(
    ctx: Context,
    resources: str | None = None,
    namespace: str | None = None,
    selector: str | None = None,
    *,
    kubectl_path: str = "kubectl",
) -> dict:
    """The `export` task's outputs: `{"dump": <ArtifactRef>, "summary":
    {returncode, bytes, stderrTail}}`."""
    argv = build_export_argv(resources or DEFAULT_RESOURCES, namespace, selector)
    return run_kubectl_to_artifact(
        ctx,
        argv,
        content_type="application/json",
        summary_model=K8sExportSummary,
        kubectl_path=kubectl_path,
    )
