from __future__ import annotations

from datetime import UTC, datetime

from rwdiscovery.rollups import (
    group_pods_by_owner,
    index_by_uid,
    index_events_by_involved_uid,
    k8s_cluster_rollup,
    k8s_cronjob_rollup,
    k8s_events_rollup,
    k8s_pods_rollup,
    k8s_service_endpoints_rollup,
    resolve_workload_owner,
)


def _pod(name, phase="Running", ready=True, restarts=0, node="acme-node-1", reason=None):
    condition = {"type": "Ready", "status": "True" if ready else "False"}
    container_status = {"restartCount": restarts, "imageID": "docker-pullable://acme/api@sha256:abc"}
    if reason:
        container_status["lastState"] = {"terminated": {"reason": reason}}
    return {
        "metadata": {"name": name, "namespace": "acme-payments", "creationTimestamp": "2026-09-20T00:00:00Z"},
        "spec": {"nodeName": node},
        "status": {"phase": phase, "conditions": [condition], "containerStatuses": [container_status]},
    }


def test_k8s_pods_rollup_empty():
    assert k8s_pods_rollup([]) == {
        "count": 0,
        "byPhase": {},
        "ready": 0,
        "restartsTotal": 0,
        "restartsMax": 0,
        "lastTerminationReasons": [],
        "nodes": [],
        "imageIds": [],
        "oldest": None,
        "newest": None,
    }


def test_k8s_pods_rollup_counts_and_reasons():
    pods = [
        _pod("api-1", restarts=2),
        _pod("api-2", phase="Failed", ready=False, restarts=5, reason="OOMKilled", node="acme-node-2"),
    ]
    rollup = k8s_pods_rollup(pods)
    assert rollup["count"] == 2
    assert rollup["byPhase"] == {"Running": 1, "Failed": 1}
    assert rollup["ready"] == 1
    assert rollup["restartsTotal"] == 7
    assert rollup["restartsMax"] == 5
    assert rollup["lastTerminationReasons"] == ["OOMKilled"]
    assert rollup["nodes"] == ["acme-node-1", "acme-node-2"]


def test_resolve_workload_owner_walks_through_replicaset():
    rs = {
        "metadata": {"uid": "rs-1", "ownerReferences": [{"kind": "Deployment", "uid": "deploy-1", "controller": True}]}
    }
    pod = {"metadata": {"ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-1", "controller": True}]}}
    owner = resolve_workload_owner(pod, {"rs-1": rs})
    assert owner == ("Deployment", "deploy-1")


def test_resolve_workload_owner_direct_statefulset():
    pod = {"metadata": {"ownerReferences": [{"kind": "StatefulSet", "uid": "sts-1", "controller": True}]}}
    assert resolve_workload_owner(pod, {}) == ("StatefulSet", "sts-1")


def test_resolve_workload_owner_orphaned_replicaset_attributes_to_replicaset():
    pod = {"metadata": {"ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-missing", "controller": True}]}}
    assert resolve_workload_owner(pod, {}) == ("ReplicaSet", "rs-missing")


def test_resolve_workload_owner_no_owner_is_none():
    assert resolve_workload_owner({"metadata": {}}, {}) is None


def test_group_pods_by_owner():
    rs = {
        "metadata": {"uid": "rs-1", "ownerReferences": [{"kind": "Deployment", "uid": "deploy-1", "controller": True}]}
    }
    pods = [
        {"metadata": {"name": "api-1", "ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-1", "controller": True}]}},
        {"metadata": {"name": "api-2", "ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-1", "controller": True}]}},
    ]
    grouped = group_pods_by_owner(pods, {"rs-1": rs})
    assert list(grouped.keys()) == [("Deployment", "deploy-1")]
    assert len(grouped[("Deployment", "deploy-1")]) == 2


def test_index_by_uid():
    items = [{"metadata": {"uid": "a"}}, {"metadata": {}}, {"metadata": {"uid": "b"}}]
    assert index_by_uid(items) == {"a": items[0], "b": items[2]}


def test_k8s_service_endpoints_rollup():
    slices = [
        {
            "endpoints": [
                {"addresses": ["10.0.0.1"], "conditions": {"ready": True}},
                {"addresses": ["10.0.0.2"], "conditions": {"ready": False}},
            ]
        }
    ]
    rollup = k8s_service_endpoints_rollup(slices)
    assert rollup == {"ready": 1, "notReady": 1, "addressCount": 2}


def test_k8s_events_rollup_filters_window_and_type():
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    events = [
        {
            "type": "Warning",
            "reason": "OOMKilling",
            "message": "Memory cgroup out of memory",
            "lastTimestamp": "2026-09-24T11:50:00+00:00",
            "count": 3,
        },
        {
            "type": "Normal",
            "reason": "Scheduled",
            "lastTimestamp": "2026-09-24T11:59:00+00:00",
        },
        {
            "type": "Warning",
            "reason": "Stale",
            "lastTimestamp": "2026-09-24T09:00:00+00:00",  # outside the 60 min window
        },
    ]
    rollup = k8s_events_rollup(events, now=now)
    assert rollup["windowMinutes"] == 60
    reasons = {w["reason"] for w in rollup["warnings"]}
    assert reasons == {"OOMKilling"}
    assert rollup["warnings"][0]["count"] == 3


def test_index_events_by_involved_uid():
    events = [
        {"involvedObject": {"uid": "pod-1"}, "reason": "Killing"},
        {"involvedObject": {"uid": "pod-2"}, "reason": "Killing"},
        {"involvedObject": {}},
    ]
    grouped = index_events_by_involved_uid(events)
    assert set(grouped.keys()) == {"pod-1", "pod-2"}


def test_k8s_cronjob_rollup_orders_and_caps_last_n():
    jobs = [
        {
            "metadata": {"name": f"acme-nightly-{i}"},
            "status": {"startTime": f"2026-09-{20 + i:02d}T00:00:00Z", "succeeded": 1},
        }
        for i in range(7)
    ]
    rollup = k8s_cronjob_rollup(jobs, last_n=5)
    assert len(rollup["lastJobs"]) == 5
    assert rollup["lastJobs"][0]["name"] == "acme-nightly-6"  # most recent first
    assert rollup["lastJobs"][0]["outcome"] == "succeeded"


def test_k8s_cronjob_rollup_marks_failed_and_running():
    jobs = [
        {"metadata": {"name": "a"}, "status": {"startTime": "2026-09-20T00:00:00Z", "failed": 1}},
        {"metadata": {"name": "b"}, "status": {"startTime": "2026-09-21T00:00:00Z"}},
    ]
    rollup = k8s_cronjob_rollup(jobs)
    by_name = {j["name"]: j["outcome"] for j in rollup["lastJobs"]}
    assert by_name == {"a": "failed", "b": "running"}


def test_k8s_cluster_rollup_infers_distribution_from_git_version():
    version_info = {"gitVersion": "v1.29.4-gke.1043004"}
    rollup = k8s_cluster_rollup(version_info, nodes=[{}, {}], api_groups=["apps", "batch"])
    assert rollup["distribution"] == "gke"
    assert rollup["nodeCount"] == 2
    assert rollup["serverVersion"] == "v1.29.4-gke.1043004"
    assert rollup["apiGroups"] == ["apps", "batch"]


def test_k8s_cluster_rollup_infers_distribution_from_node_labels_when_version_is_generic():
    version_info = {"gitVersion": "v1.29.4"}
    nodes = [{"metadata": {"labels": {"eks.amazonaws.com/nodegroup": "default"}}}]
    rollup = k8s_cluster_rollup(version_info, nodes=nodes, api_groups=[])
    assert rollup["distribution"] == "eks"


def test_k8s_cluster_rollup_unknown_distribution():
    rollup = k8s_cluster_rollup({"gitVersion": "v1.29.4"}, nodes=[{"metadata": {}}], api_groups=[])
    assert rollup["distribution"] == "unknown"


def test_k8s_cluster_rollup_omits_node_count_when_nodes_unavailable():
    """`nodes=None` means the Node listing itself 403'd/errored -- `nodeCount`
    must never be reported as a false zero. `distribution` and the rest stay
    (they don't depend on having read any nodes), falling back to the
    version-string markers alone rather than the node-label inference."""
    rollup = k8s_cluster_rollup({"gitVersion": "v1.29.4-gke.1043004"}, nodes=None, api_groups=["apps", "batch"])
    assert "nodeCount" not in rollup
    assert rollup["distribution"] == "gke"
    assert rollup["serverVersion"] == "v1.29.4-gke.1043004"
    assert rollup["apiGroups"] == ["apps", "batch"]


def test_k8s_cluster_rollup_unknown_distribution_when_nodes_unavailable_and_version_is_generic():
    rollup = k8s_cluster_rollup({"gitVersion": "v1.29.4"}, nodes=None, api_groups=[])
    assert rollup["distribution"] == "unknown"
    assert "nodeCount" not in rollup


def test_k8s_events_rollup_masks_credentials_before_truncating_the_message():
    """Masking after the 300-char cut would leave a DSN's '@' outside the
    window, so the password prefix inside it would no longer match."""
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    event = {
        "type": "Warning",
        "reason": "ConnectFailed",
        "message": "a" * 280 + "postgres://app:s3cretpw@acme-db.acme-payments.svc:5432/orders",
        "lastTimestamp": "2026-09-24T11:59:00Z",
    }
    message = k8s_events_rollup([event], now=now)["warnings"][0]["message"]
    assert "s3cr" not in message
    assert len(message) == 300
