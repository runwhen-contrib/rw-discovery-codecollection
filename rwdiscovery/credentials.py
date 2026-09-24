"""Materialises the `k8s.kubeconfig` credential (platform-contract §4) into a
`kubernetes.client.ApiClient`, confined to the request's own scope
directory.

The kubeconfig string never touches an ambient location -- no
`~/.kube/config`, no `KUBECONFIG` env var (which would also race across
concurrent tasks in one process: `inspect`'s `maxConcurrentPerPod` is 4).
It is written to a temp file INSIDE `workdir` (the request's scope
directory, per `Context.workdir`), and the kubernetes client library's own
incidental temp files -- materialised from inline base64 CA/cert/key data,
`kube_config.py`'s `FileOrData` -- are redirected into the same directory
via `temp_file_path`, so the whole credential footprint is wiped when the
task host cleans up the scope, none of it lingers in the pod's shared
`/tmp`, and the raw kubeconfig file itself is deleted the moment it has
been loaded.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from kubernetes import client, config
from kubernetes.config import kube_config as _kube_config


class KubeconfigError(RuntimeError):
    """Raised when the resolved kubeconfig credential cannot be loaded --
    malformed YAML, an unsupported auth plugin, or similar. Distinct from
    the k8s API errors raised once the client is actually in use."""


def build_api_client(kubeconfig_yaml: str, workdir: Path) -> client.ApiClient:
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(dir=workdir, prefix=".kubeconfig-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(kubeconfig_yaml)
        configuration = client.Configuration()
        _forget_foreign_temp_files(workdir)
        try:
            config.load_kube_config(
                config_file=raw_path,
                client_configuration=configuration,
                persist_config=False,  # never write back (e.g. refreshed exec-plugin tokens) to our temp file
                temp_file_path=str(workdir),
            )
        except Exception as exc:  # noqa: BLE001 -- any parse/auth-plugin failure collapses to one error class
            raise KubeconfigError(f"could not load the kubeconfig credential: {exc}") from exc
        return client.ApiClient(configuration=configuration)
    finally:
        try:
            os.unlink(raw_path)
        except OSError:
            pass


def _forget_foreign_temp_files(workdir: Path) -> None:
    """Drop the kubernetes client's cached temp files that live outside `workdir`.

    `kube_config` caches the file it writes for inline CA/cert/key data in a
    module-level dict keyed by the data alone, ignoring `temp_file_path`. In a
    warm executor pod the next request with the same cluster CA is handed the
    PREVIOUS request's file, whose scope directory the task host has already
    wiped -- "File does not exist" -- and even while it exists, one request
    must not read another's credential material. Forgetting every entry
    outside this request's workdir makes each load write its own copy here.
    """
    root = os.path.realpath(workdir) + os.sep
    for key, path in list(_kube_config._temp_files.items()):  # noqa: SLF001 -- no public API for this cache
        if not os.path.realpath(path).startswith(root):
            _kube_config._temp_files.pop(key, None)  # noqa: SLF001
