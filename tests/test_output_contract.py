"""discover's returned dict must validate against rwdiscovery.models -- the
schema a manifest references is only useful if the task's actual output
shape matches it.

`inspect` was retired in favour of `cli` (platform-contract §7); its own
`rw.k8s_object.v1` output is still published (schema files never change or
disappear once published) but no task produces it any more, so there is no
live output to validate here -- see `rwdiscovery/models.py`'s
`K8sObjectResult` docstring."""

from __future__ import annotations

from pathlib import Path

import responses

from rwdiscovery.discover import run_discover
from rwdiscovery.models import DiscoverySummary
from tests.test_discover_e2e import _build_fake_cluster, _FakePapi, _resource_sync_credential_raw


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
