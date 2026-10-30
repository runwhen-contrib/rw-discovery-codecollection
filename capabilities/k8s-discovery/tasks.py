# @setup / @task functions -- thin; the logic lives in rwdiscovery/ (a real
# installed package, not a capability-local module -- see
# rwdiscovery/__init__.py and this repo's pyproject.toml). Mirrors
# rw-checks-codecollection's capabilities/rw-checks/tasks.py shape.
from __future__ import annotations

from runwhen_capability import Context, setup, task

from rwdiscovery import cli as cli_lib
from rwdiscovery import connect as connect_lib
from rwdiscovery import discover as discover_lib
from rwdiscovery import export as export_lib
from rwdiscovery import logs as logs_lib


@setup(outputs=["serverVersion", "clusterUid"])
def connect(ctx: Context, context: str | None = None):
    return connect_lib.connect(ctx.credential("kubeconfig"), ctx.workdir, context=context)


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


@task(outputs={"result": "rw.cli_result.v2"})
def cli(
    ctx: Context,
    cluster_name: str,
    argv: list[str],
    max_bytes: int | None = None,
    timeout_seconds: int | None = None,
):
    result = cli_lib.run_cli(
        kubeconfig_yaml=ctx.credential("kubeconfig"),
        argv=argv,
        workdir=ctx.workdir,
        max_bytes=max_bytes,
        timeout_seconds=timeout_seconds,
        cluster_name=cluster_name,
    )
    return {"result": result}


@task(outputs={"dump": "artifact", "summary": "rw.k8s_export_summary.v1"})
def export(
    ctx: Context,
    cluster_name: str,
    resources: str | None = None,
    namespace: str | None = None,
    selector: str | None = None,
):
    return export_lib.run_export(ctx, resources=resources, namespace=namespace, selector=selector)


@task(outputs={"dump": "artifact", "summary": "rw.k8s_logs_summary.v1"})
def logs(
    ctx: Context,
    cluster_name: str,
    namespace: str,
    selector: str | None = None,
    workload: str | None = None,
    since: str | None = None,
    container: str | None = None,
):
    return logs_lib.run_logs(
        ctx, namespace=namespace, selector=selector, workload=workload, since=since, container=container
    )
