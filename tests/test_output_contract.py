"""discover/inspect's returned dicts must validate against
rwdiscovery.models -- the schema a manifest references is only useful if
the task's actual output shape matches it."""

from __future__ import annotations

from pathlib import Path

import responses

from rwdiscovery.discover import run_discover
from rwdiscovery.inspect import run_inspect
from rwdiscovery.models import DiscoverySummary, K8sObjectResult
from tests.test_discover_e2e import _build_fake_cluster, _FakePapi, _resource_sync_credential_raw
from tests.test_inspect import _fake_cluster_with_deployment


@responses.activate
def test_discover_summary_matches_its_declared_schema(tmp_path: Path):
    fake_papi = _FakePapi()
    fake_papi.install()
    summary = run_discover(
        kubeconfig_yaml="unused",
        resource_sync_raw=_resource_sync_credential_raw(),
        cluster_name="acme-prod-eu",
        namespaces=None,
        exclude_namespaces=None,
        config_map_values="store",
        overlay=None,
        workdir=tmp_path,
        k8s_client=_build_fake_cluster(),
    )
    DiscoverySummary.model_validate(summary)  # must not raise


def test_inspect_get_result_matches_its_declared_schema(tmp_path: Path):
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="acme-api",
        namespace="acme-payments",
        api_version="apps/v1",
        mode="get",
        workdir=tmp_path,
        k8s_client=_fake_cluster_with_deployment(),
    )
    K8sObjectResult.model_validate(result)


def test_inspect_not_found_result_matches_its_declared_schema(tmp_path: Path):
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="does-not-exist",
        namespace="acme-payments",
        api_version="apps/v1",
        mode="get",
        workdir=tmp_path,
        k8s_client=_fake_cluster_with_deployment(),
    )
    K8sObjectResult.model_validate(result)
