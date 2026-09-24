# @setup / @task functions -- thin; the logic lives in rwdiscovery/ (a real
# installed package, not a capability-local module -- see
# rwdiscovery/__init__.py and this repo's pyproject.toml). Mirrors
# rw-checks-codecollection's capabilities/rw-checks/tasks.py shape.
from __future__ import annotations

from runwhen_capability import Context, setup, task

from rwdiscovery import connect as connect_lib
from rwdiscovery import discover as discover_lib
from rwdiscovery import inspect as inspect_lib


@setup(outputs=["serverVersion", "clusterUid"])
def connect(ctx: Context):
    return connect_lib.connect(ctx.credential("kubeconfig"), ctx.workdir)


@task(outputs={"summary": "rw.discovery_summary.v1"})
def discover(
    ctx: Context,
    cluster_name: str,
    namespaces: list[str] | None = None,
    exclude_namespaces: list[str] | None = None,
    config_map_values: str | None = None,
    overlay: dict | None = None,
    context: str | None = None,
):
    summary = discover_lib.run_discover(
        kubeconfig_yaml=ctx.credential("kubeconfig"),
        resource_sync_raw=ctx.credential("resourceSync"),
        cluster_name=cluster_name,
        namespaces=namespaces,
        exclude_namespaces=exclude_namespaces,
        config_map_values=config_map_values or "store",
        overlay=overlay,
        workdir=ctx.workdir,
        context=context,
    )
    return {"summary": summary}


@task(outputs={"object": "rw.k8s_object.v1"})
def inspect(
    ctx: Context,
    cluster_name: str,
    kind: str,
    name: str,
    mode: str,
    namespace: str | None = None,
    api_version: str | None = None,
    context: str | None = None,
):
    result = inspect_lib.run_inspect(
        kubeconfig_yaml=ctx.credential("kubeconfig"),
        cluster_name=cluster_name,
        kind=kind,
        name=name,
        namespace=namespace,
        api_version=api_version,
        mode=mode,
        workdir=ctx.workdir,
        context=context,
    )
    return {"object": result}
