"""The `connect` setup task's logic (platform-contract §5): materialise
the kubeconfig, check access, read server version + kube-system UID. Runs
once per request, before `discover` or `inspect` -- if the cluster is
unreachable, the whole request fails here, before either task starts.

Its outputs (`serverVersion`, `clusterUid`) are small, JSON-serializable
facts a task references as `${setup.serverVersion}`/`${setup.clusterUid}`.
The `kubernetes.client.ApiClient` itself can't cross that boundary (it
isn't JSON), so `discover`/`inspect` each rebuild their own from the same
`kubeconfig` credential -- cheap, and the only shape the wire format
allows (host.py's `RequestEnvelope`/`ResultEnvelope`).
"""

from __future__ import annotations

from pathlib import Path

from . import credentials
from .k8s_client import K8sClient

KUBE_SYSTEM_PATH = "/api/v1/namespaces/kube-system"


def connect(kubeconfig_yaml: str, workdir: Path) -> dict:
    api_client = credentials.build_api_client(kubeconfig_yaml, workdir)
    k8s = K8sClient(api_client)
    version_info = k8s.get_raw("/version")
    kube_system = k8s.get_object(KUBE_SYSTEM_PATH)
    # This resource's providerUid is the kube-system namespace UID -- a
    # stable per-cluster identifier (OTel's k8s.cluster.uid) that lets papi
    # notice when the same cluster gets registered under two different names.
    cluster_uid = (kube_system or {}).get("metadata", {}).get("uid", "")
    return {
        "serverVersion": version_info.get("gitVersion", ""),
        "clusterUid": cluster_uid,
    }
