from __future__ import annotations

import dataclasses

from rwdiscovery.rollup_context import NamespaceRollupContext


def _pod(name, owner_uid, ready=True):
    return {
        "metadata": {
            "name": name,
            "uid": f"pod-{name}",
            "namespace": "acme-payments",
            "ownerReferences": [{"kind": "ReplicaSet", "uid": owner_uid, "controller": True}],
        },
        "spec": {"nodeName": "acme-node-1"},
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [{"restartCount": 0, "imageID": "sha256:abc"}],
        },
    }


def test_pods_rollup_for_deployment_via_replicaset():
    rs = {
        "metadata": {"uid": "rs-1", "ownerReferences": [{"kind": "Deployment", "uid": "deploy-1", "controller": True}]}
    }
    pods = [_pod("api-1", "rs-1"), _pod("api-2", "rs-1")]
    ctx = NamespaceRollupContext.build("acme-payments", pods, [rs], [], [], [])
    result = ctx.rollups_for("deployment", "deploy-1", "api")
    assert result["k8sPods"]["count"] == 2
    assert "k8sEvents" in result


def test_service_endpoints_rollup_by_service_name_label():
    endpointslice = {
        "metadata": {"labels": {"kubernetes.io/service-name": "acme-api"}},
        "endpoints": [{"addresses": ["10.0.0.1"], "conditions": {"ready": True}}],
    }
    ctx = NamespaceRollupContext.build("acme-payments", [], [], [endpointslice], [], [])
    result = ctx.rollups_for("service", "svc-uid-1", "acme-api")
    assert result["k8sServiceEndpoints"]["ready"] == 1


def test_cronjob_rollup_by_owner_uid():
    job = {
        "metadata": {"name": "acme-nightly-1", "ownerReferences": [{"kind": "CronJob", "uid": "cj-1"}]},
        "status": {"startTime": "2026-09-20T00:00:00Z", "succeeded": 1},
    }
    ctx = NamespaceRollupContext.build("acme-payments", [], [], [], [job], [])
    result = ctx.rollups_for("cronjob", "cj-1", "acme-nightly")
    assert result["k8sCronJobRuns"]["lastJobs"][0]["name"] == "acme-nightly-1"


def test_events_attributed_to_pods_reach_the_owning_workload():
    rs = {
        "metadata": {"uid": "rs-1", "ownerReferences": [{"kind": "Deployment", "uid": "deploy-1", "controller": True}]}
    }
    pods = [_pod("api-1", "rs-1")]
    event = {
        "type": "Warning",
        "reason": "OOMKilling",
        "involvedObject": {"uid": "pod-api-1"},
        "lastTimestamp": "2026-09-24T11:59:00+00:00",
    }
    ctx = NamespaceRollupContext.build("acme-payments", pods, [rs], [], [], [event])
    result = ctx.rollups_for("deployment", "deploy-1", "api")
    reasons = {w["reason"] for w in result["k8sEvents"]["warnings"]}
    assert "OOMKilling" in reasons


def test_replicasets_unavailable_omits_k8s_pods():
    """ReplicaSets map a Deployment's pods to it -- without them, a pod
    owned via a ReplicaSet can't be attributed to the Deployment at all
    (see `resolve_workload_owner`'s orphaned-RS fallback), so the whole
    facet must be omitted rather than look like zero pods."""
    pods = [_pod("api-1", "rs-1")]
    ctx = NamespaceRollupContext.build("acme-payments", pods, [], [], [], [], unavailable_sources=["replicaset"])
    result = ctx.rollups_for("deployment", "deploy-1", "api")
    assert "k8sPods" not in result


def test_pods_unavailable_omits_k8s_pods_but_keeps_direct_events():
    """A workload's own events (as opposed to its pods') don't need the pod
    listing to be attributed correctly, so k8sEvents stays -- only k8sPods
    (which needs the pods themselves) is omitted."""
    event = {
        "type": "Warning",
        "reason": "FailedScale",
        "involvedObject": {"uid": "deploy-1"},
        "lastTimestamp": "2026-09-24T11:59:00+00:00",
    }
    ctx = NamespaceRollupContext.build("acme-payments", [], [], [], [], [event], unavailable_sources=["pod"])
    result = ctx.rollups_for("deployment", "deploy-1", "api")
    assert "k8sPods" not in result
    assert {w["reason"] for w in result["k8sEvents"]["warnings"]} == {"FailedScale"}


def test_events_unavailable_omits_k8s_events():
    ctx = NamespaceRollupContext.build("acme-payments", [], [], [], [], [], unavailable_sources=["event"])
    result = ctx.rollups_for("deployment", "deploy-1", "api")
    assert "k8sEvents" not in result


def test_endpointslices_unavailable_omits_k8s_service_endpoints():
    ctx = NamespaceRollupContext.build("acme-payments", [], [], [], [], [], unavailable_sources=["endpointslice"])
    result = ctx.rollups_for("service", "svc-uid-1", "acme-api")
    assert "k8sServiceEndpoints" not in result


def test_jobs_unavailable_omits_k8s_cronjob_runs():
    ctx = NamespaceRollupContext.build("acme-payments", [], [], [], [], [], unavailable_sources=["job"])
    result = ctx.rollups_for("cronjob", "cj-1", "acme-nightly")
    assert "k8sCronJobRuns" not in result


def test_a_real_empty_namespace_still_gets_a_true_zero_k8s_pods():
    """Every source is readable and genuinely empty here -- this is not a
    permissions gap, so the facet must still be reported, with a real
    zero count."""
    ctx = NamespaceRollupContext.build("acme-payments", [], [], [], [], [])
    result = ctx.rollups_for("deployment", "deploy-1", "api")
    assert result["k8sPods"]["count"] == 0


def test_context_retains_compact_values_not_raw_objects():
    """One context per in-scope namespace lives for the whole run, so it
    must not hold the raw pods/events it was built from."""
    rs = {
        "metadata": {"uid": "rs-1", "ownerReferences": [{"kind": "Deployment", "uid": "deploy-1", "controller": True}]}
    }
    normal = {"type": "Normal", "reason": "Pulled", "involvedObject": {"uid": "pod-api-1"}}
    ctx = NamespaceRollupContext.build("acme-payments", [_pod("api-1", "rs-1")], [rs], [], [], [normal])
    retained = repr(dataclasses.asdict(ctx))
    assert "containerStatuses" not in retained  # no raw pod
    assert "Pulled" not in retained  # only Warning events are kept
    assert ctx.rollups_for("deployment", "deploy-1", "api")["k8sPods"]["count"] == 1
