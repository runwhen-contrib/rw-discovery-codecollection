"""The `connect` setup task's logic (platform-contract §5): materialise
the kubeconfig, check access, read server version + kube-system UID. Runs
once per request, before `discover` or `cli` -- if the cluster is
unreachable, the whole request fails here, before either task starts.

Its outputs (`serverVersion`, `clusterUid`) are small, JSON-serializable
facts a task references as `${setup.serverVersion}`/`${setup.clusterUid}`.
The `kubernetes.client.ApiClient` itself can't cross that boundary (it
isn't JSON), so `discover` rebuilds its own from the same `kubeconfig`
credential -- cheap, and the only shape the wire format allows (host.py's
`RequestEnvelope`/`ResultEnvelope`). `cli` takes a different path entirely:
it writes the same credential straight to a file for the real `kubectl`
binary's own `--kubeconfig` flag, never building an `ApiClient` at all
(`cli.py`).
"""

from __future__ import annotations

from pathlib import Path

from . import credentials
from .k8s_client import ForbiddenError, K8sClient

KUBE_SYSTEM_PATH = "/api/v1/namespaces/kube-system"


def connect(kubeconfig_yaml: str, workdir: Path, context: str | None = None) -> dict:
    """`context` selects a named kubeconfig context to build this
    reachability check from, instead of the kubeconfig's current-context --
    the same input `discover` accepts (`cli` has none of its own, §7), so
    this precheck actually covers the context a scheduled run is configured
    with, not just the kubeconfig's default one."""
    api_client = credentials.build_api_client(kubeconfig_yaml, workdir, context=context)
    k8s = K8sClient(api_client)
    version_info = k8s.get_raw("/version")
    return {
        "serverVersion": version_info.get("gitVersion", ""),
        "clusterUid": read_cluster_uid(k8s),
    }


def read_cluster_uid(k8s: K8sClient) -> str:
    """The kube-system namespace UID, or "" when it cannot be read.

    It is a stable per-cluster identifier (OTel's k8s.cluster.uid) that lets
    papi notice the same cluster registered under two names -- useful, never
    required. A namespace-scoped credential cannot read a cluster-scoped
    Namespace object, and that must not fail the whole run: the cluster item
    is then pushed without a providerUid.
    """
    try:
        kube_system = k8s.get_object(KUBE_SYSTEM_PATH)
    except ForbiddenError:
        return ""
    return (kube_system or {}).get("metadata", {}).get("uid", "")
