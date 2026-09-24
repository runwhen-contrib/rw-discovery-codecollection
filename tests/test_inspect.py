from __future__ import annotations

import json
from pathlib import Path

import pytest

from rwdiscovery.inspect import run_inspect
from tests.fakes import FakeK8sClient


def _fake_cluster_with_deployment(include_events=True) -> FakeK8sClient:
    single = {
        "/apis": {
            "groups": [
                {
                    "name": "apps",
                    "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
                    "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                }
            ]
        },
        "/api/v1": {"resources": []},
        "/apis/apps/v1": {
            "resources": [{"name": "deployments", "kind": "Deployment", "namespaced": True, "verbs": ["get", "list"]}]
        },
        "/apis/apps/v1/namespaces/acme-payments/deployments/acme-api": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "acme-api",
                "namespace": "acme-payments",
                "uid": "deploy-uid-1",
                "creationTimestamp": "2026-09-01T00:00:00Z",
                "labels": {"app": "acme-api"},
            },
            "spec": {"replicas": 2, "selector": {"matchLabels": {"app": "acme-api"}}},
            "status": {"readyReplicas": 2, "conditions": [{"type": "Available", "status": "True"}]},
        },
    }
    if include_events:
        single["/api/v1/namespaces/acme-payments/events"] = {
            "items": [
                {
                    "type": "Normal",
                    "reason": "ScalingReplicaSet",
                    "message": "Scaled up replica set acme-api-7d9f to 2",
                    "lastTimestamp": "2026-09-24T00:00:00Z",
                    "involvedObject": {"uid": "deploy-uid-1"},
                }
            ]
        }
    return FakeK8sClient(single=single)


def test_inspect_get_mode_returns_sanitized_object_and_path(tmp_path: Path):
    fake = _fake_cluster_with_deployment()
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="acme-api",
        namespace="acme-payments",
        api_version="apps/v1",
        mode="get",
        workdir=tmp_path,
        k8s_client=fake,
    )
    assert result["found"] is True
    assert result["path"] == "kubernetes/clusters/acme-prod-eu/namespaces/acme-payments/deployments/acme-api"
    assert result["object"]["spec"]["replicas"] == 2
    assert result["object"]["status"]["readyReplicas"] == 2


def test_inspect_describe_mode_renders_text_and_events(tmp_path: Path):
    fake = _fake_cluster_with_deployment()
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="acme-api",
        namespace="acme-payments",
        api_version="apps/v1",
        mode="describe",
        workdir=tmp_path,
        k8s_client=fake,
    )
    assert result["found"] is True
    assert "Kind:        Deployment" in result["describe"]
    assert "acme-api" in result["describe"]
    assert len(result["events"]) == 1
    assert result["events"][0]["reason"] == "ScalingReplicaSet"


def test_inspect_not_found_returns_found_false_with_computed_path(tmp_path: Path):
    fake = _fake_cluster_with_deployment()
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="does-not-exist",
        namespace="acme-payments",
        api_version="apps/v1",
        mode="get",
        workdir=tmp_path,
        k8s_client=fake,
    )
    assert result["found"] is False
    assert result["path"] == "kubernetes/clusters/acme-prod-eu/namespaces/acme-payments/deployments/does-not-exist"
    assert "object" not in result


def test_inspect_resolves_kind_without_explicit_api_version(tmp_path: Path):
    fake = _fake_cluster_with_deployment()
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="acme-api",
        namespace="acme-payments",
        api_version=None,
        mode="get",
        workdir=tmp_path,
        k8s_client=fake,
    )
    assert result["found"] is True


def test_inspect_never_exposes_secret_values():
    """Sanity check that inspect's `get` mode goes through the same
    sanitizer as discover -- a Secret's data must never appear."""
    fake = FakeK8sClient(
        single={
            "/apis": {"groups": []},
            "/api/v1": {
                "resources": [{"name": "secrets", "kind": "Secret", "namespaced": True, "verbs": ["get", "list"]}]
            },
            "/api/v1/namespaces/acme-payments/secrets/acme-db-creds": {
                "apiVersion": "v1",
                "kind": "Secret",
                "type": "Opaque",
                "metadata": {"name": "acme-db-creds", "namespace": "acme-payments", "uid": "secret-uid-1"},
                "data": {"password": "aHVudGVyMg=="},
            },
        }
    )
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Secret",
        name="acme-db-creds",
        namespace="acme-payments",
        api_version="v1",
        mode="get",
        workdir=Path("/tmp"),
        k8s_client=fake,
    )
    assert "data" not in result["object"]
    assert result["object"]["secretKeys"] == ["password"]


# --- agent-supplied inputs and events ---


def _inspect(fake, **overrides):
    kwargs = dict(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="acme-api",
        namespace="acme-payments",
        api_version="apps/v1",
        mode="get",
        workdir=Path("/tmp"),
        k8s_client=fake,
    )
    kwargs.update(overrides)
    return run_inspect(**kwargs)


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": "../secrets/acme-db-creds"},
        {"name": ".."},
        {"name": "acme-api%2F..%2Fproxy"},
        {"namespace": "../../../api/v1/nodes/acme-node-1/proxy"},
        {"api_version": "v1/../../api/v1/namespaces/acme-payments/services/acme-api:80/proxy"},
        {"mode": "exec"},
    ],
)
def test_inspect_refuses_inputs_that_would_address_another_api_path(overrides):
    """`inspect`'s inputs come from an agent. A `/`, `..` or `%` in a name
    (or a malformed apiVersion) would turn a GET of one object into a GET of
    any API path the kubeconfig can reach -- services/proxy, nodes/proxy."""
    fake = _fake_cluster_with_deployment()
    with pytest.raises(ValueError):
        _inspect(fake, **overrides)
    assert not any(".." in path or "proxy" in path for path, _ in fake.calls)


def test_inspect_percent_encodes_query_and_fragment_characters_in_names():
    fake = _fake_cluster_with_deployment()
    _inspect(fake, name="acme?watch=true#x")
    assert "/apis/apps/v1/namespaces/acme-payments/deployments/acme%3Fwatch%3Dtrue%23x" in [p for p, _ in fake.calls]


def test_inspect_describe_events_are_sanitized_and_filtered_server_side():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQdLp6uT9c2y8IyOFPFJKfhCEG_ppEZmvo"
    fake = _fake_cluster_with_deployment()
    fake.single["/api/v1/namespaces/acme-payments/events"]["items"][0].update(
        {
            "message": f"probe failed: GET http://acme-api/health?token={jwt}",
            "metadata": {"name": "acme-api.1", "managedFields": [{"manager": "kubelet"}]},
        }
    )
    result = _inspect(fake, mode="describe")
    assert jwt not in json.dumps(result)
    assert "managedFields" not in result["events"][0]["metadata"]
    events_call = next(q for p, q in fake.calls if p.endswith("/events"))
    assert ("fieldSelector", "involvedObject.uid=deploy-uid-1") in events_call


# --- logs mode (log-patterns-v0 platform-contract §1.3) ---------------------


def _pod(name: str, *, ready: bool = True, restarts: int = 0) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": "acme-payments", "uid": f"{name}-uid"},
        "spec": {"containers": [{"name": "api"}, {"name": "sidecar"}]},
        "status": {
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [{"name": "api", "restartCount": restarts}, {"name": "sidecar", "restartCount": 0}],
        },
    }


def _fake_cluster_for_logs() -> FakeK8sClient:
    fake = _fake_cluster_with_deployment(include_events=False)
    fake.single["/api/v1/namespaces/acme-payments/pods"] = {
        "items": [_pod("acme-api-healthy"), _pod("acme-api-unhealthy", ready=False, restarts=3)]
    }
    fake.text["/api/v1/namespaces/acme-payments/pods/acme-api-healthy/log"] = "line one\nline two\n"
    fake.text["/api/v1/namespaces/acme-payments/pods/acme-api-unhealthy/log"] = "boom\nERROR still broken\n"
    return fake


def _inspect_logs(fake, **overrides):
    kwargs = dict(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Deployment",
        name="acme-api",
        namespace="acme-payments",
        api_version="apps/v1",
        mode="logs",
        workdir=Path("/tmp"),
        k8s_client=fake,
    )
    kwargs.update(overrides)
    return run_inspect(**kwargs)


def test_inspect_logs_mode_resolves_workload_pods_and_reads_every_container():
    fake = _fake_cluster_for_logs()
    result = _inspect_logs(fake, max_pods=2)
    obj = result["object"]
    assert obj["mode"] == "logs"
    # unhealthy pod first, one entry per container
    assert obj["pods"][0]["pod"] == "acme-api-unhealthy"
    pods_seen = {(p["pod"], p["container"]) for p in obj["pods"]}
    assert pods_seen == {
        ("acme-api-unhealthy", "api"),
        ("acme-api-unhealthy", "sidecar"),
        ("acme-api-healthy", "api"),
        ("acme-api-healthy", "sidecar"),
    }
    unhealthy_api = next(p for p in obj["pods"] if p["pod"] == "acme-api-unhealthy" and p["container"] == "api")
    assert unhealthy_api["lines"] == ["boom", "ERROR still broken"]
    assert unhealthy_api["error"] is None
    assert obj["totalLines"] == sum(len(p["lines"]) for p in obj["pods"])


def test_inspect_logs_mode_max_pods_caps_and_marks_truncated():
    fake = _fake_cluster_for_logs()
    result = _inspect_logs(fake, max_pods=1)
    obj = result["object"]
    assert {p["pod"] for p in obj["pods"]} == {"acme-api-unhealthy"}  # unhealthy pod wins the one slot
    assert obj["truncated"] is True


def test_inspect_logs_mode_container_filter_reads_only_that_container():
    fake = _fake_cluster_for_logs()
    result = _inspect_logs(fake, container="api", max_pods=1)
    obj = result["object"]
    assert [p["container"] for p in obj["pods"]] == ["api"]


def test_inspect_logs_mode_previous_flag_is_passed_through_and_recorded():
    fake = _fake_cluster_for_logs()
    result = _inspect_logs(fake, container="api", max_pods=1, previous=True)
    obj = result["object"]
    assert obj["pods"][0]["previous"] is True
    log_call = next(q for p, q in fake.calls if p.endswith("/acme-api-unhealthy/log"))
    assert ("previous", "true") in log_call


def test_inspect_logs_mode_grep_filters_before_tail_is_taken():
    fake = _fake_cluster_for_logs()
    fake.text["/api/v1/namespaces/acme-payments/pods/acme-api-healthy/log"] = "\n".join(
        [f"info line {i}" for i in range(5)] + ["ERROR disk full"]
    )
    result = _inspect_logs(fake, container="api", max_pods=2, grep="error")
    healthy = next(p for p in result["object"]["pods"] if p["pod"] == "acme-api-healthy")
    assert healthy["lines"] == ["ERROR disk full"]


def test_inspect_logs_mode_tail_lines_keeps_only_the_last_n():
    fake = _fake_cluster_for_logs()
    fake.text["/api/v1/namespaces/acme-payments/pods/acme-api-healthy/log"] = "\n".join(f"line {i}" for i in range(10))
    result = _inspect_logs(fake, container="api", max_pods=2, tail_lines=3)
    healthy = next(p for p in result["object"]["pods"] if p["pod"] == "acme-api-healthy")
    assert healthy["lines"] == ["line 7", "line 8", "line 9"]
    assert healthy["truncated"] is True


def test_inspect_logs_mode_invalid_grep_reports_a_clear_error_not_a_crash():
    fake = _fake_cluster_for_logs()
    result = _inspect_logs(fake, grep="(unclosed")
    obj = result["object"]
    assert obj["pods"] == []
    assert obj["error"]
    assert "invalid grep" in obj["error"]


def test_inspect_logs_mode_forbidden_pod_log_is_reported_per_entry():
    fake = _fake_cluster_for_logs()
    fake.forbidden.add("/api/v1/namespaces/acme-payments/pods/acme-api-unhealthy/log")
    result = _inspect_logs(fake, container="api", max_pods=1)
    entry = result["object"]["pods"][0]
    assert entry["error"] == "forbidden"
    assert entry["lines"] == []


def test_inspect_logs_mode_caps_line_length():
    fake = _fake_cluster_for_logs()
    fake.text["/api/v1/namespaces/acme-payments/pods/acme-api-healthy/log"] = "x" * 5000
    result = _inspect_logs(fake, container="api", max_pods=2)
    healthy = next(p for p in result["object"]["pods"] if p["pod"] == "acme-api-healthy")
    assert len(healthy["lines"][0]) == 2000
    assert healthy["truncated"] is True


def test_inspect_logs_mode_bare_pod_reads_that_pod_directly():
    fake = _fake_cluster_for_logs()
    fake.single["/api/v1"] = {
        "resources": [{"name": "pods", "kind": "Pod", "namespaced": True, "verbs": ["get", "list"]}]
    }
    fake.single["/api/v1/namespaces/acme-payments/pods/acme-api-healthy"] = _pod("acme-api-healthy")
    result = run_inspect(
        kubeconfig_yaml="unused",
        cluster_name="acme-prod-eu",
        kind="Pod",
        name="acme-api-healthy",
        namespace="acme-payments",
        api_version="v1",
        mode="logs",
        workdir=Path("/tmp"),
        container="api",
        k8s_client=fake,
    )
    assert result["object"]["pods"][0]["pod"] == "acme-api-healthy"
    assert result["object"]["pods"][0]["lines"] == ["line one", "line two"]
