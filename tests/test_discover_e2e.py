"""End-to-end test of `discover` against a fake Kubernetes API
(`tests/fakes.py`'s `FakeK8sClient`) and a fake papi (`responses`).
Asserts batches, seq idempotency-friendliness, commit partitions and the
summary result -- platform-contract §3/§5.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
import responses

from rwdiscovery.discover import run_discover
from rwdiscovery.sync import SyncClientError
from tests.fakes import FakeK8sClient

API_BASE = "https://papi.acme.internal"
WORKSPACE = "acme-workspace"


def _resource_sync_credential_raw() -> str:
    return json.dumps({"apiBaseUrl": API_BASE, "token": "jwt-token", "workspace": WORKSPACE})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _build_fake_cluster() -> FakeK8sClient:
    namespace = "acme-payments"
    return FakeK8sClient(
        single={
            "/version": {"gitVersion": "v1.29.4-gke.1043004", "major": "1", "minor": "29"},
            "/api/v1/namespaces/kube-system": {"metadata": {"name": "kube-system", "uid": "kube-system-uid-1"}},
            "/apis": {
                "groups": [
                    {
                        "name": "apps",
                        "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
                        "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                    },
                    {
                        "name": "batch",
                        "preferredVersion": {"groupVersion": "batch/v1", "version": "v1"},
                        "versions": [{"groupVersion": "batch/v1", "version": "v1"}],
                    },
                    {
                        "name": "discovery.k8s.io",
                        "preferredVersion": {"groupVersion": "discovery.k8s.io/v1", "version": "v1"},
                        "versions": [{"groupVersion": "discovery.k8s.io/v1", "version": "v1"}],
                    },
                ]
            },
            "/api/v1": {
                "resources": [
                    {"name": "namespaces", "kind": "Namespace", "namespaced": False, "verbs": ["get", "list"]},
                    {"name": "nodes", "kind": "Node", "namespaced": False, "verbs": ["get", "list"]},
                    {"name": "pods", "kind": "Pod", "namespaced": True, "verbs": ["get", "list"]},
                    {"name": "services", "kind": "Service", "namespaced": True, "verbs": ["get", "list"]},
                    {"name": "configmaps", "kind": "ConfigMap", "namespaced": True, "verbs": ["get", "list"]},
                    {"name": "secrets", "kind": "Secret", "namespaced": True, "verbs": ["get", "list"]},
                    {"name": "events", "kind": "Event", "namespaced": True, "verbs": ["get", "list"]},
                ]
            },
            "/apis/apps/v1": {
                "resources": [
                    {"name": "deployments", "kind": "Deployment", "namespaced": True, "verbs": ["get", "list"]},
                    {"name": "replicasets", "kind": "ReplicaSet", "namespaced": True, "verbs": ["get", "list"]},
                ]
            },
            "/apis/batch/v1": {
                "resources": [
                    {"name": "jobs", "kind": "Job", "namespaced": True, "verbs": ["get", "list"]},
                    {"name": "cronjobs", "kind": "CronJob", "namespaced": True, "verbs": ["get", "list"]},
                ]
            },
            "/apis/discovery.k8s.io/v1": {
                "resources": [
                    {"name": "endpointslices", "kind": "EndpointSlice", "namespaced": True, "verbs": ["get", "list"]},
                ]
            },
            "/api/v1/namespaces": {"items": [{"metadata": {"name": namespace, "uid": "ns-uid-1", "labels": {}}}]},
        },
        pages={
            "/api/v1/nodes": [
                {
                    "items": [
                        {
                            "apiVersion": "v1",
                            "kind": "Node",
                            "metadata": {
                                "name": "acme-node-1",
                                "uid": "node-uid-1",
                                "labels": {"topology.kubernetes.io/zone": "us-east-1a"},
                            },
                            "spec": {},
                            "status": {
                                "nodeInfo": {"kubeletVersion": "v1.29.4"},
                                "conditions": [{"type": "Ready", "status": "True"}],
                            },
                        }
                    ]
                }
            ],
            "/apis/apps/v1/deployments": [
                {
                    "items": [
                        {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "acme-api",
                                "namespace": namespace,
                                "uid": "deploy-uid-1",
                                "labels": {"app": "acme-api"},
                            },
                            "spec": {
                                "replicas": 2,
                                "selector": {"matchLabels": {"app": "acme-api"}},
                                "template": {
                                    "metadata": {"labels": {"app": "acme-api"}},
                                    "spec": {
                                        "serviceAccountName": "acme-api-sa",
                                        "containers": [
                                            {
                                                "name": "api",
                                                "image": "acme/api:1.2.3",
                                                "env": [{"name": "DB_PASSWORD", "value": "hunter2"}],
                                            }
                                        ],
                                    },
                                },
                            },
                            "status": {"replicas": 2, "readyReplicas": 2, "availableReplicas": 2, "updatedReplicas": 2},
                        }
                    ]
                }
            ],
            "/api/v1/services": [
                {
                    "items": [
                        {
                            "apiVersion": "v1",
                            "kind": "Service",
                            "metadata": {"name": "acme-api", "namespace": namespace, "uid": "svc-uid-1"},
                            "spec": {
                                "type": "ClusterIP",
                                "clusterIP": "10.0.0.5",
                                "selector": {"app": "acme-api"},
                                "ports": [{"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}],
                            },
                            "status": {},
                        }
                    ]
                }
            ],
            "/api/v1/configmaps": [
                {
                    "items": [
                        {
                            "apiVersion": "v1",
                            "kind": "ConfigMap",
                            "metadata": {"name": "acme-app-config", "namespace": namespace, "uid": "cm-uid-1"},
                            "data": {
                                "database.conf": "url=postgres://app:s3cr3t@acme-db.acme-payments.svc:5432/orders"
                            },
                        }
                    ]
                }
            ],
            "/api/v1/secrets": [
                {
                    "items": [
                        {
                            "apiVersion": "v1",
                            "kind": "Secret",
                            "metadata": {"name": "acme-db-creds", "namespace": namespace, "uid": "secret-uid-1"},
                            "type": "Opaque",
                            "data": {"password": "c2VjcmV0"},
                        }
                    ]
                }
            ],
            "/apis/batch/v1/cronjobs": [
                {
                    "items": [
                        {
                            "apiVersion": "batch/v1",
                            "kind": "CronJob",
                            "metadata": {"name": "acme-nightly", "namespace": namespace, "uid": "cronjob-uid-1"},
                            "spec": {"schedule": "0 2 * * *"},
                            "status": {"lastScheduleTime": "2026-09-24T02:00:00Z"},
                        }
                    ]
                }
            ],
            "/apis/batch/v1/jobs": [
                {
                    "items": [
                        {
                            "apiVersion": "batch/v1",
                            "kind": "Job",
                            "metadata": {
                                "name": "acme-nightly-28000000",
                                "namespace": namespace,
                                "uid": "job-uid-1",
                                "ownerReferences": [
                                    {"kind": "CronJob", "name": "acme-nightly", "uid": "cronjob-uid-1"}
                                ],
                            },
                            "status": {"startTime": "2026-09-24T02:00:00Z", "succeeded": 1},
                        }
                    ]
                }
            ],
            f"/api/v1/namespaces/{namespace}/pods": [
                {
                    "items": [
                        {
                            "apiVersion": "v1",
                            "kind": "Pod",
                            "metadata": {
                                "name": "acme-api-7d9f9c-aaaa",
                                "namespace": namespace,
                                "uid": "pod-uid-1",
                                "ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-uid-1", "controller": True}],
                            },
                            "spec": {"nodeName": "acme-node-1"},
                            "status": {
                                "phase": "Running",
                                "conditions": [{"type": "Ready", "status": "True"}],
                                "containerStatuses": [{"restartCount": 0, "imageID": "sha256:abc"}],
                            },
                        },
                        {
                            "apiVersion": "v1",
                            "kind": "Pod",
                            "metadata": {
                                "name": "acme-api-7d9f9c-bbbb",
                                "namespace": namespace,
                                "uid": "pod-uid-2",
                                "ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-uid-1", "controller": True}],
                            },
                            "spec": {"nodeName": "acme-node-1"},
                            "status": {
                                "phase": "Running",
                                "conditions": [{"type": "Ready", "status": "True"}],
                                "containerStatuses": [{"restartCount": 0, "imageID": "sha256:abc"}],
                            },
                        },
                    ]
                }
            ],
            f"/apis/apps/v1/namespaces/{namespace}/replicasets": [
                {
                    "items": [
                        {
                            "apiVersion": "apps/v1",
                            "kind": "ReplicaSet",
                            "metadata": {
                                "name": "acme-api-7d9f9c",
                                "namespace": namespace,
                                "uid": "rs-uid-1",
                                "ownerReferences": [
                                    {
                                        "kind": "Deployment",
                                        "name": "acme-api",
                                        "uid": "deploy-uid-1",
                                        "controller": True,
                                    }
                                ],
                            },
                            "spec": {},
                            "status": {},
                        }
                    ]
                }
            ],
            f"/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices": [
                {
                    "items": [
                        {
                            "apiVersion": "discovery.k8s.io/v1",
                            "kind": "EndpointSlice",
                            "metadata": {
                                "name": "acme-api-abcde",
                                "namespace": namespace,
                                "uid": "eps-uid-1",
                                "labels": {"kubernetes.io/service-name": "acme-api"},
                            },
                            "endpoints": [{"addresses": ["10.1.0.5"], "conditions": {"ready": True}}],
                        }
                    ]
                }
            ],
            f"/apis/batch/v1/namespaces/{namespace}/jobs": [
                {
                    "items": [
                        {
                            "apiVersion": "batch/v1",
                            "kind": "Job",
                            "metadata": {
                                "name": "acme-nightly-28000000",
                                "namespace": namespace,
                                "uid": "job-uid-1",
                                "ownerReferences": [
                                    {"kind": "CronJob", "name": "acme-nightly", "uid": "cronjob-uid-1"}
                                ],
                            },
                            "status": {"startTime": "2026-09-24T02:00:00Z", "succeeded": 1},
                        }
                    ]
                }
            ],
            f"/api/v1/namespaces/{namespace}/events": [
                {
                    "items": [
                        {
                            "type": "Warning",
                            "reason": "BackOff",
                            "message": "Back-off restarting failed container",
                            "involvedObject": {"kind": "Pod", "uid": "pod-uid-1", "name": "acme-api-7d9f9c-aaaa"},
                            "lastTimestamp": _now_iso(),
                        }
                    ]
                }
            ],
        },
    )


class _FakePapi:
    """Records every /items POST (seq + item count) and /commit POST
    (partitions body) so the test can assert on them, and serves plausible
    responses so run_discover's own bookkeeping (totals, commit counts)
    has something real to fold in."""

    def __init__(self):
        self.item_batches: list[dict] = []
        self.pushed_items: list[dict] = []
        self.commit_calls: list[dict] = []

    def install(self):
        responses.add(
            responses.PUT,
            f"{API_BASE}/api/v4/workspaces/{WORKSPACE}/resource-packs/kubernetes",
            json={"name": "kubernetes", "version": "0.1.0", "digest": "irrelevant", "registered": True, "counts": {}},
            status=200,
        )
        responses.add(
            responses.POST,
            f"{API_BASE}/api/v4/workspaces/{WORKSPACE}/resource-syncs",
            json={"syncId": "sync-1", "leaseExpiresAt": "2026-09-24T13:00:00Z"},
            status=201,
        )
        responses.add_callback(
            responses.POST,
            f"{API_BASE}/api/v4/workspaces/{WORKSPACE}/resource-syncs/sync-1/items",
            callback=self._on_items,
            content_type="application/json",
        )
        responses.add_callback(
            responses.POST,
            f"{API_BASE}/api/v4/workspaces/{WORKSPACE}/resource-syncs/sync-1/commit",
            callback=self._on_commit,
            content_type="application/json",
        )

    def _on_items(self, request):
        body = json.loads(request.body)
        self.item_batches.append(body)
        self.pushed_items.extend(body["items"])
        response = {
            "seq": body["seq"],
            "accepted": len(body["items"]),
            "created": len(body["items"]),
            "updated": 0,
            "unchanged": 0,
            "rejected": [],
        }
        return (200, {}, json.dumps(response))

    def _on_commit(self, request):
        body = json.loads(request.body)
        self.commit_calls.append(body)
        created = sum(len(b["items"]) for b in self.item_batches)
        response = {
            "status": "committed",
            "counts": {"created": created, "updated": 0, "unchanged": 0, "deleted": 0, "held": 0},
        }
        return (200, {}, json.dumps(response))

    def item_by_type_and_name(self, type_name: str, name: str) -> dict:
        for item in self.pushed_items:
            chain = item["identity"]["chain"]
            last = chain[-1]
            if last["type"] == type_name and last["name"] == name:
                return item
        raise AssertionError(f"no pushed item found for {type_name}/{name}")


@responses.activate
def test_discover_end_to_end(tmp_path: Path):
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()

    summary = run_discover(
        kubeconfig_yaml="unused-because-k8s_client-is-injected",
        resource_sync_raw=_resource_sync_credential_raw(),
        cluster_name="acme-prod-eu",
        namespaces=None,
        exclude_namespaces=None,
        config_map_values="store",
        overlay=None,
        workdir=tmp_path,
        capability_run_uuid="run-uuid-1",
        k8s_client=fake_k8s,
    )

    # --- summary shape (platform-contract §5 rw.discovery_summary.v1) ---
    assert summary["syncId"] == "sync-1"
    assert summary["serverVersion"] == "v1.29.4-gke.1043004"
    assert summary["clusterUid"] == "kube-system-uid-1"
    assert summary["counts"]["created"] > 0
    assert summary["partitions"]["complete"] > 0
    assert summary["partitions"]["forbidden"] == 0
    assert summary["partitions"]["failed"] == 0
    assert isinstance(summary["durationMs"], int)
    # papi's canonical digest (from the PUT response) is authoritative, and the
    # PUT body itself carries no digest (platform-contract §2).
    assert summary["packDigest"] == "irrelevant"
    pack_put = next(c for c in responses.calls if c.request.method == "PUT")
    assert "digest" not in json.loads(pack_put.request.body)

    # --- seq is monotonic starting at 1 across every /items call (platform-contract §3) ---
    seqs = [batch["seq"] for batch in fake_papi.item_batches]
    assert seqs == list(range(1, len(seqs) + 1))

    # --- push order: cluster, then namespaces, then the rest ---
    first_item = fake_papi.pushed_items[0]
    assert first_item["identity"]["chain"] == [{"type": "cluster", "name": "acme-prod-eu"}]
    second_item = fake_papi.pushed_items[1]
    assert second_item["identity"]["chain"][-1] == {"type": "namespace", "name": "acme-payments"}

    # --- the cluster item carries the k8sCluster rollup ---
    assert first_item["rollups"]["k8sCluster"]["distribution"] == "gke"
    assert first_item["rollups"]["k8sCluster"]["nodeCount"] == 1

    # --- sanitization ran end to end: ConfigMap DSN password masked, host/db kept ---
    configmap_item = fake_papi.item_by_type_and_name("configmap", "acme-app-config")
    assert "s3cr3t" not in json.dumps(configmap_item["document"])
    assert "acme-db.acme-payments.svc:5432/orders" in configmap_item["document"]["data"]["database.conf"]

    # --- Secret data/stringData removed, key names only ---
    secret_item = fake_papi.item_by_type_and_name("secret", "acme-db-creds")
    assert "data" not in secret_item["document"]
    assert secret_item["document"]["secretKeys"] == ["password"]

    # --- env value masked by narrow key name, end to end ---
    deployment_item = fake_papi.item_by_type_and_name("deployment", "acme-api")
    env = deployment_item["document"]["spec"]["template"]["spec"]["containers"][0]["env"]
    assert env[0]["value"] == "***MASKED:credential***"

    # --- pods rollup attached to the Deployment (via ReplicaSet) ---
    assert deployment_item["rollups"]["k8sPods"]["count"] == 2
    assert deployment_item["rollups"]["k8sPods"]["ready"] == 2
    # events attributed through the pod up to the deployment
    warning_reasons = {w["reason"] for w in deployment_item["rollups"]["k8sEvents"]["warnings"]}
    assert "BackOff" in warning_reasons

    # --- service endpoints rollup ---
    service_item = fake_papi.item_by_type_and_name("service", "acme-api")
    assert service_item["rollups"]["k8sServiceEndpoints"]["ready"] == 1

    # --- CronJob's last-run rollup sees the Job it owns ---
    cronjob_item = fake_papi.item_by_type_and_name("cronjob", "acme-nightly")
    assert cronjob_item["rollups"]["k8sCronJobRuns"]["lastJobs"][0]["name"] == "acme-nightly-28000000"

    # --- the Job owned by that CronJob is never pushed as its own item (per-object ephemeral) ---
    with_job = [i for i in fake_papi.pushed_items if i["identity"]["chain"][-1]["type"] == "job"]
    assert with_job == []

    # --- Node (cluster-scoped, non-ephemeral) is pushed ---
    node_item = fake_papi.item_by_type_and_name("node", "acme-node-1")
    assert node_item["identity"]["chain"] == [
        {"type": "cluster", "name": "acme-prod-eu"},
        {"type": "node", "name": "acme-node-1"},
    ]

    # --- commit partitions: one per (type, parentPath) listed, cluster path for cluster-scoped/namespace-listing ---
    commit_body = fake_papi.commit_calls[0]
    partitions_by_type = {}
    for p in commit_body["partitions"]:
        partitions_by_type.setdefault(p["type"], []).append(p)
    assert partitions_by_type["namespace"][0]["status"] == "complete"
    assert partitions_by_type["namespace"][0]["parentPath"] == "kubernetes/clusters/acme-prod-eu"
    assert (
        partitions_by_type["deployment"][0]["parentPath"] == "kubernetes/clusters/acme-prod-eu/namespaces/acme-payments"
    )
    assert partitions_by_type["node"][0]["parentPath"] == "kubernetes/clusters/acme-prod-eu"
    for partitions in partitions_by_type.values():
        for p in partitions:
            assert p["status"] == "complete"


@responses.activate
def test_discover_propagates_a_fatal_discovery_error_before_ever_opening_a_sync(tmp_path: Path):
    """A hard failure enumerating the API itself (`/api/v1` blows up --
    unlike a per-type/per-namespace listing failure, `discover_resources()`
    does not treat this as one type's partition and lets it propagate) now
    happens before the pack is even registered: every listable type needs
    a TypeSpec registered up front (packbuild.extra_discovered_type_specs),
    so the one discovery sweep feeding that has to run before the pack PUT,
    which itself has to run before `open_sync` carries its digest. There is
    therefore no sync to abort -- papi is never contacted at all."""
    fake_papi = _FakePapi()
    fake_papi.install()

    fake_k8s = _build_fake_cluster()
    fake_k8s.errors["/api/v1"] = (500, "internal error")

    try:
        run_discover(
            kubeconfig_yaml="unused",
            resource_sync_raw=_resource_sync_credential_raw(),
            cluster_name="acme-prod-eu",
            namespaces=None,
            exclude_namespaces=None,
            config_map_values="store",
            overlay=None,
            workdir=tmp_path,
            k8s_client=fake_k8s,
        )
    except Exception:
        pass
    else:
        raise AssertionError("expected run_discover to propagate the fatal error")

    assert len(responses.calls) == 0  # papi never contacted -- no PUT, no open, nothing to abort


@responses.activate
def test_discover_aborts_the_sync_on_a_fatal_error_after_it_is_open(tmp_path: Path):
    """A hard failure once the sync IS open (here: pushing items fails
    outright, a non-retryable status) must abort it rather than leave it
    dangling -- platform-contract §3. This runs after `_push_cluster_and_
    namespaces` and `_push_everything_else` have already queued the
    cluster/namespace/resource items locally, so it also proves that
    queued-but-never-flushed work is safely abandoned, never committed."""
    base = f"{API_BASE}/api/v4/workspaces/{WORKSPACE}"
    responses.add(responses.PUT, f"{base}/resource-packs/kubernetes", json={"digest": "d"}, status=200)
    responses.add(responses.POST, f"{base}/resource-syncs", json={"syncId": "sync-1"}, status=201)
    responses.add(responses.POST, f"{base}/resource-syncs/sync-1/items", json={"errors": ["bad"]}, status=422)
    abort_calls: list = []
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/abort",
        callback=lambda request: (abort_calls.append(json.loads(request.body)), (200, {}, "{}"))[1],
        content_type="application/json",
    )
    commit_calls: list = []
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/commit",
        callback=lambda request: (commit_calls.append(json.loads(request.body)), (200, {}, "{}"))[1],
        content_type="application/json",
    )

    try:
        run_discover(
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
    except Exception:
        pass
    else:
        raise AssertionError("expected run_discover to propagate the fatal error")

    assert len(abort_calls) == 1
    assert commit_calls == []  # aborted, never committed -- the queued push is abandoned


def _strip_list_item_type_meta(fake: FakeK8sClient) -> FakeK8sClient:
    """What a real API server does: list items of built-in types carry no
    kind/apiVersion."""
    for pages in fake.pages.values():
        for page in pages:
            for item in page.get("items", []):
                item.pop("kind", None)
                item.pop("apiVersion", None)
    return fake


def _run(fake_k8s: FakeK8sClient, tmp_path: Path, config_map_values: str = "store") -> dict:
    return run_discover(
        kubeconfig_yaml="unused",
        resource_sync_raw=_resource_sync_credential_raw(),
        cluster_name="acme-prod-eu",
        namespaces=None,
        exclude_namespaces=None,
        config_map_values=config_map_values,
        overlay=None,
        workdir=tmp_path,
        k8s_client=fake_k8s,
    )


@responses.activate
def test_discover_sanitizes_list_items_that_carry_no_kind(tmp_path: Path):
    """Secret/ConfigMap handling dispatches on `kind`, which list items from
    a real API server don't carry -- without the listing's type stamped on,
    a Secret's `data` left the cluster and `keysOnly` was ignored."""
    fake_papi = _FakePapi()
    fake_papi.install()
    _run(_strip_list_item_type_meta(_build_fake_cluster()), tmp_path, config_map_values="keysOnly")

    secret_item = fake_papi.item_by_type_and_name("secret", "acme-db-creds")
    assert "data" not in secret_item["document"]
    assert "c2VjcmV0" not in json.dumps(secret_item)
    assert secret_item["document"]["secretKeys"] == ["password"]
    assert secret_item["document"]["kind"] == "Secret"

    configmap_item = fake_papi.item_by_type_and_name("configmap", "acme-app-config")
    assert "data" not in configmap_item["document"]  # keysOnly honoured
    assert "database.conf" in configmap_item["document"]["dataHashes"]

    namespace_item = fake_papi.item_by_type_and_name("namespace", "acme-payments")
    assert namespace_item["document"]["kind"] == "Namespace"


@responses.activate
def test_event_rollups_read_core_events_when_events_k8s_io_is_served(tmp_path: Path):
    """Every cluster since 1.19 serves events.k8s.io/v1 too. Its Event has
    `regarding`/`note`, not `involvedObject`/`message`; the rollups must
    keep reading core/v1 events."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.single["/apis"]["groups"].append(
        {
            "name": "events.k8s.io",
            "preferredVersion": {"groupVersion": "events.k8s.io/v1", "version": "v1"},
            "versions": [{"groupVersion": "events.k8s.io/v1", "version": "v1"}],
        }
    )
    fake_k8s.single["/apis/events.k8s.io/v1"] = {
        "resources": [{"name": "events", "kind": "Event", "namespaced": True, "verbs": ["get", "list"]}]
    }
    fake_k8s.pages["/apis/events.k8s.io/v1/namespaces/acme-payments/events"] = [
        {"items": [{"type": "Warning", "reason": "BackOff", "regarding": {"uid": "pod-uid-1"}, "note": "x"}]}
    ]
    _run(fake_k8s, tmp_path)

    deployment_item = fake_papi.item_by_type_and_name("deployment", "acme-api")
    assert "BackOff" in {w["reason"] for w in deployment_item["rollups"]["k8sEvents"]["warnings"]}


@responses.activate
def test_pack_registration_covers_an_aggregated_api_type_not_in_builtins_or_crds(tmp_path: Path):
    """`apiregistration.k8s.io/APIService` is neither a chain.py builtin nor
    backed by a CustomResourceDefinition object -- without registering a
    TypeSpec for it too, papi would reject every pushed APIService item as
    an unknown type (platform-contract §3)."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.single["/apis"]["groups"].append(
        {
            "name": "apiregistration.k8s.io",
            "preferredVersion": {"groupVersion": "apiregistration.k8s.io/v1", "version": "v1"},
            "versions": [{"groupVersion": "apiregistration.k8s.io/v1", "version": "v1"}],
        }
    )
    fake_k8s.single["/apis/apiregistration.k8s.io/v1"] = {
        "resources": [{"name": "apiservices", "kind": "APIService", "namespaced": False, "verbs": ["get", "list"]}]
    }
    fake_k8s.pages["/apis/apiregistration.k8s.io/v1/apiservices"] = [
        {"items": [{"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService", "metadata": {"name": "v1.apps"}}]}
    ]
    _run(fake_k8s, tmp_path)

    pack_put = next(c for c in responses.calls if c.request.method == "PUT")
    pack_put_body = json.loads(pack_put.request.body)
    # additive (platform-contract §2): this cluster's own discovery, not the static part.
    additive_types = {t["type"] for t in pack_put_body["additiveTypes"]}
    assert "apiservice.apiregistration.k8s.io" in additive_types
    assert "apiservice.apiregistration.k8s.io" not in {t["type"] for t in pack_put_body["types"]}
    apiservice_item = fake_papi.item_by_type_and_name("apiservice.apiregistration.k8s.io", "v1.apps")
    assert apiservice_item["identity"]["chain"] == [
        {"type": "cluster", "name": "acme-prod-eu"},
        {"type": "apiservice.apiregistration.k8s.io", "name": "v1.apps"},
    ]


@responses.activate
def test_pack_registration_skipped_entries_are_logged_not_fatal(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    """platform-contract §2: an additive type conflicting with an
    existing registration comes back as a `skipped` entry, not a failing
    status -- the whole run must still complete. Items of that type still
    get pushed and are left to the existing rejected-item handling
    (`test_rejected_item_fails_its_partition_and_is_never_swept`) to fail
    their own partition; this test only covers that a skip is surfaced,
    not swallowed silently."""
    base = f"{API_BASE}/api/v4/workspaces/{WORKSPACE}"
    fake_papi = _FakePapi()
    responses.add(
        responses.PUT,
        f"{base}/resource-packs/kubernetes",
        json={
            "name": "kubernetes",
            "version": "0.1.0",
            "digest": "irrelevant",
            "registered": True,
            "counts": {},
            "skipped": [{"type": "widget.acme.io", "reason": "plural_conflict"}],
        },
        status=200,
    )
    responses.add(
        responses.POST,
        f"{base}/resource-syncs",
        json={"syncId": "sync-1", "leaseExpiresAt": "2026-09-24T13:00:00Z"},
        status=201,
    )
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/items",
        callback=fake_papi._on_items,
        content_type="application/json",
    )
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/commit",
        callback=fake_papi._on_commit,
        content_type="application/json",
    )

    with caplog.at_level(logging.WARNING, logger="rwdiscovery.sync"):
        summary = _run(_build_fake_cluster(), tmp_path)

    assert summary["partitions"]["failed"] == 0  # the skip itself never fails anything
    assert any("widget.acme.io" in r.message and "plural_conflict" in r.message for r in caplog.records)


@responses.activate
def test_rejected_item_fails_its_partition_and_is_never_swept(tmp_path: Path):
    """platform-contract §3: an unknown type / bad chain is rejected,
    never stored. The sync client must not silently treat that partition
    as complete -- it must be reported failed at commit, so papi never
    sweeps resources of that type that simply weren't re-observed this
    run because the push itself was rejected."""
    fake_papi = _FakePapi()

    def _on_items_with_one_rejection(request):
        body = json.loads(request.body)
        fake_papi.item_batches.append(body)
        fake_papi.pushed_items.extend(body["items"])
        configmap_index = next(
            i for i, item in enumerate(body["items"]) if item["identity"]["chain"][-1]["type"] == "configmap"
        )
        response = {
            "seq": body["seq"],
            "accepted": len(body["items"]) - 1,
            "created": len(body["items"]) - 1,
            "updated": 0,
            "unchanged": 0,
            "rejected": [{"index": configmap_index, "code": "parent_missing", "detail": "namespace not found"}],
        }
        return (200, {}, json.dumps(response))

    # Not fake_papi.install(): its /items callback always succeeds, and
    # `responses` has no in-place way to replace a callback response --
    # register the same routes by hand, with the rejecting /items callback.
    base = f"{API_BASE}/api/v4/workspaces/{WORKSPACE}"
    responses.add(
        responses.PUT,
        f"{base}/resource-packs/kubernetes",
        json={"name": "kubernetes", "version": "0.1.0", "digest": "irrelevant", "registered": True, "counts": {}},
        status=200,
    )
    responses.add(
        responses.POST,
        f"{base}/resource-syncs",
        json={"syncId": "sync-1", "leaseExpiresAt": "2026-09-24T13:00:00Z"},
        status=201,
    )
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/items",
        callback=_on_items_with_one_rejection,
        content_type="application/json",
    )
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/commit",
        callback=fake_papi._on_commit,
        content_type="application/json",
    )

    _run(_build_fake_cluster(), tmp_path)

    commit_body = fake_papi.commit_calls[0]
    partitions_by_type = {p["type"]: p for p in commit_body["partitions"]}
    assert partitions_by_type["configmap"]["status"] == "failed"
    assert "parent_missing" in partitions_by_type["configmap"]["reason"]
    assert "count" not in partitions_by_type["configmap"]  # failed partitions carry no count
    # every other partition is unaffected
    assert partitions_by_type["deployment"]["status"] == "complete"
    assert partitions_by_type["namespace"]["status"] == "complete"


def _run_with_namespaces(fake_k8s: FakeK8sClient, tmp_path: Path, namespaces: list[str]) -> dict:
    return run_discover(
        kubeconfig_yaml="unused",
        resource_sync_raw=_resource_sync_credential_raw(),
        cluster_name="acme-prod-eu",
        namespaces=namespaces,
        exclude_namespaces=None,
        config_map_values="store",
        overlay=None,
        workdir=tmp_path,
        k8s_client=fake_k8s,
    )


@responses.activate
def test_namespace_listing_forbidden_with_explicit_namespaces_gets_each_individually(tmp_path: Path):
    """A minimal-privilege ServiceAccount is commonly granted `get` on
    specific namespaces but not a cluster-wide `list` -- when `namespaces`
    is explicit, that must not sink the whole namespace partition or leave
    namespaced children without a parent."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/api/v1/namespaces")
    fake_k8s.single["/api/v1/namespaces/acme-payments"] = {
        "metadata": {"name": "acme-payments", "uid": "ns-uid-1", "labels": {"team": "payments"}}
    }

    _run_with_namespaces(fake_k8s, tmp_path, ["acme-payments"])

    namespace_item = fake_papi.item_by_type_and_name("namespace", "acme-payments")
    assert namespace_item["document"]["kind"] == "Namespace"
    assert namespace_item["labels"] == {"team": "payments"}
    # The deployment in that namespace still gets a valid parent chain.
    deployment_item = fake_papi.item_by_type_and_name("deployment", "acme-api")
    assert {"type": "namespace", "name": "acme-payments"} in deployment_item["identity"]["chain"]

    commit_body = fake_papi.commit_calls[0]
    namespace_partition = next(p for p in commit_body["partitions"] if p["type"] == "namespace")
    # Never swept: an explicit per-namespace GET can't prove no other
    # namespace exists or was deleted.
    assert namespace_partition["status"] == "forbidden"
    assert "count" not in namespace_partition


@responses.activate
def test_namespace_get_also_forbidden_pushes_a_stub_item(tmp_path: Path):
    """Even the individual GET can 403/404 -- push a stub (identity chain
    only, a marker annotation) rather than dropping it, so anything
    readable underneath it still has a parent to attach to."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/api/v1/namespaces")
    fake_k8s.forbidden.add("/api/v1/namespaces/acme-restricted")

    _run_with_namespaces(fake_k8s, tmp_path, ["acme-restricted"])

    namespace_item = fake_papi.item_by_type_and_name("namespace", "acme-restricted")
    assert namespace_item["document"]["metadata"]["annotations"]["k8s-discovery.runwhen.com/stub"] == "true"
    assert "uid" not in namespace_item["document"]["metadata"]


def _install_papi_with_failing_commit(fake_papi: _FakePapi, abort_status: int, abort_calls: list) -> None:
    base = f"{API_BASE}/api/v4/workspaces/{WORKSPACE}"
    responses.add(responses.PUT, f"{base}/resource-packs/kubernetes", json={"digest": "d"}, status=200)
    responses.add(responses.POST, f"{base}/resource-syncs", json={"syncId": "sync-1"}, status=201)
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/items",
        callback=fake_papi._on_items,
        content_type="application/json",
    )
    responses.add(responses.POST, f"{base}/resource-syncs/sync-1/commit", json={"errors": ["bad"]}, status=422)
    responses.add_callback(
        responses.POST,
        f"{base}/resource-syncs/sync-1/abort",
        callback=lambda request: (abort_calls.append(json.loads(request.body)), (abort_status, {}, "{}"))[1],
        content_type="application/json",
    )


@responses.activate
def test_discover_aborts_the_sync_when_commit_fails(tmp_path: Path):
    abort_calls: list = []
    _install_papi_with_failing_commit(_FakePapi(), 200, abort_calls)
    with pytest.raises(SyncClientError, match="/commit: 422"):
        _run(_build_fake_cluster(), tmp_path)
    assert len(abort_calls) == 1


@responses.activate
def test_a_failing_abort_never_masks_the_original_error(tmp_path: Path):
    abort_calls: list = []
    _install_papi_with_failing_commit(_FakePapi(), 400, abort_calls)
    with pytest.raises(SyncClientError, match="/commit: 422"):
        _run(_build_fake_cluster(), tmp_path)
    assert len(abort_calls) == 1


@responses.activate
def test_a_namespace_scoped_credential_that_cannot_read_kube_system_still_discovers(tmp_path: Path):
    """kube-system is a cluster-scoped Namespace object; a credential bound
    only inside one namespace cannot read it. The cluster UID is a nice-to-have
    identifier, so the run proceeds and the cluster item carries no providerUid."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/api/v1/namespaces/kube-system")

    summary = _run_with_namespaces(fake_k8s, tmp_path, ["acme-payments"])

    assert summary["clusterUid"] == ""
    cluster_item = fake_papi.item_by_type_and_name("cluster", "acme-prod-eu")
    assert "providerUid" not in cluster_item
    assert fake_papi.item_by_type_and_name("deployment", "acme-api") is not None


def _add_second_namespace(fake: FakeK8sClient, namespace: str = "acme-batch") -> FakeK8sClient:
    """A second, fully-readable namespace with its own Deployment and the
    rollup sources for it, so a test can 403 one specific rollup source in
    ONE namespace and prove the other namespace's rollups are unaffected."""
    fake.single["/api/v1/namespaces"]["items"].append({"metadata": {"name": namespace, "uid": f"{namespace}-uid"}})
    fake.pages["/apis/apps/v1/deployments"][0]["items"].append(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "acme-worker", "namespace": namespace, "uid": "deploy-uid-2"},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "acme-worker"}}},
            "status": {"replicas": 1, "readyReplicas": 1},
        }
    )
    fake.pages[f"/api/v1/namespaces/{namespace}/pods"] = [
        {
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "acme-worker-aaaa",
                        "namespace": namespace,
                        "uid": "pod-uid-worker-1",
                        "ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-uid-worker", "controller": True}],
                    },
                    "spec": {"nodeName": "acme-node-1"},
                    "status": {
                        "phase": "Running",
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "containerStatuses": [{"restartCount": 0}],
                    },
                }
            ]
        }
    ]
    fake.pages[f"/apis/apps/v1/namespaces/{namespace}/replicasets"] = [
        {
            "items": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "metadata": {
                        "name": "acme-worker-aaaa",
                        "namespace": namespace,
                        "uid": "rs-uid-worker",
                        "ownerReferences": [
                            {"kind": "Deployment", "name": "acme-worker", "uid": "deploy-uid-2", "controller": True}
                        ],
                    },
                }
            ]
        }
    ]
    fake.pages[f"/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices"] = [{"items": []}]
    fake.pages[f"/apis/batch/v1/namespaces/{namespace}/jobs"] = [{"items": []}]
    fake.pages[f"/api/v1/namespaces/{namespace}/events"] = [{"items": []}]
    return fake


@responses.activate
def test_pods_forbidden_in_one_namespace_omits_k8s_pods_there_but_not_in_a_readable_namespace(tmp_path: Path):
    """A credential that can list Deployments but not Pods in a given
    namespace must not make every workload there look like it has zero
    pods -- and must not affect a namespace where pods ARE readable."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _add_second_namespace(_build_fake_cluster())
    fake_k8s.forbidden.add("/api/v1/namespaces/acme-batch/pods")

    _run(fake_k8s, tmp_path)

    worker_item = fake_papi.item_by_type_and_name("deployment", "acme-worker")
    assert "k8sPods" not in worker_item["rollups"]

    api_item = fake_papi.item_by_type_and_name("deployment", "acme-api")
    assert api_item["rollups"]["k8sPods"]["count"] == 2


@responses.activate
def test_replicasets_forbidden_omits_k8s_pods(tmp_path: Path):
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/apis/apps/v1/namespaces/acme-payments/replicasets")

    _run(fake_k8s, tmp_path)

    deployment_item = fake_papi.item_by_type_and_name("deployment", "acme-api")
    assert "k8sPods" not in deployment_item["rollups"]


@responses.activate
def test_events_forbidden_omits_k8s_events(tmp_path: Path):
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/api/v1/namespaces/acme-payments/events")

    _run(fake_k8s, tmp_path)

    deployment_item = fake_papi.item_by_type_and_name("deployment", "acme-api")
    assert "k8sEvents" not in deployment_item["rollups"]


@responses.activate
def test_pods_forbidden_but_events_readable_keeps_direct_events(tmp_path: Path):
    """A workload's own events (as opposed to its pods') don't need the pod
    listing -- k8sEvents stays, carrying only what it can still prove."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.pages["/api/v1/namespaces/acme-payments/events"][0]["items"].append(
        {
            "type": "Warning",
            "reason": "FailedScale",
            "message": "forbid scaling",
            "involvedObject": {"kind": "Deployment", "uid": "deploy-uid-1", "name": "acme-api"},
            "lastTimestamp": _now_iso(),
        }
    )
    fake_k8s.forbidden.add("/api/v1/namespaces/acme-payments/pods")

    _run(fake_k8s, tmp_path)

    deployment_item = fake_papi.item_by_type_and_name("deployment", "acme-api")
    assert "k8sPods" not in deployment_item["rollups"]
    reasons = {w["reason"] for w in deployment_item["rollups"]["k8sEvents"]["warnings"]}
    assert "FailedScale" in reasons
    assert "BackOff" not in reasons  # pod-attributed; can't be attributed without reading pods


@responses.activate
def test_endpointslices_forbidden_omits_k8s_service_endpoints(tmp_path: Path):
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/apis/discovery.k8s.io/v1/namespaces/acme-payments/endpointslices")

    _run(fake_k8s, tmp_path)

    service_item = fake_papi.item_by_type_and_name("service", "acme-api")
    assert "k8sServiceEndpoints" not in service_item["rollups"]


@responses.activate
def test_nodes_forbidden_omits_node_count_but_keeps_the_rest_of_k8s_cluster(tmp_path: Path):
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/api/v1/nodes")

    summary = _run(fake_k8s, tmp_path)

    cluster_item = fake_papi.item_by_type_and_name("cluster", "acme-prod-eu")
    assert "nodeCount" not in cluster_item["rollups"]["k8sCluster"]
    assert cluster_item["rollups"]["k8sCluster"]["serverVersion"] == "v1.29.4-gke.1043004"
    assert cluster_item["rollups"]["k8sCluster"]["distribution"] == "gke"  # inferred from gitVersion alone
    assert summary["rollupSourcesUnavailable"][""] == ["node"]


@responses.activate
def test_a_real_empty_namespace_still_gets_a_true_zero_pod_count(tmp_path: Path):
    """Every rollup source is actually readable and genuinely empty here --
    that's a real fact, not a permissions gap, and must still be reported."""
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _add_second_namespace(_build_fake_cluster())
    fake_k8s.pages["/api/v1/namespaces/acme-batch/pods"] = [{"items": []}]
    fake_k8s.pages["/apis/apps/v1/namespaces/acme-batch/replicasets"] = [{"items": []}]

    _run(fake_k8s, tmp_path)

    worker_item = fake_papi.item_by_type_and_name("deployment", "acme-worker")
    assert worker_item["rollups"]["k8sPods"]["count"] == 0


@responses.activate
def test_summary_reports_which_rollup_sources_were_unavailable(tmp_path: Path):
    fake_papi = _FakePapi()
    fake_papi.install()
    fake_k8s = _build_fake_cluster()
    fake_k8s.forbidden.add("/api/v1/namespaces/acme-payments/pods")
    fake_k8s.forbidden.add("/api/v1/nodes")

    summary = _run(fake_k8s, tmp_path)

    assert summary["rollupSourcesUnavailable"]["acme-payments"] == ["pod"]
    assert summary["rollupSourcesUnavailable"][""] == ["node"]
