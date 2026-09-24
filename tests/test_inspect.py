from __future__ import annotations

import json
from pathlib import Path

import pytest

import rwdiscovery.credentials as credentials
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
            "spec": {"replicas": 2},
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


def test_run_inspect_forwards_context_to_build_api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """`context` (manifest input, optional) must reach `build_api_client`
    unchanged, so it can select a named kubeconfig context instead of
    current-context. Only exercised when `k8s_client` isn't supplied --
    every other test in this file injects a fake client and never touches
    `credentials.build_api_client` at all."""
    captured: dict = {}

    class _Stop(Exception):
        pass

    def _fake_build_api_client(kubeconfig_yaml, workdir, context=None):
        captured["context"] = context
        raise _Stop

    monkeypatch.setattr(credentials, "build_api_client", _fake_build_api_client)

    with pytest.raises(_Stop):
        run_inspect(
            kubeconfig_yaml="unused",
            cluster_name="acme-prod-eu",
            kind="Deployment",
            name="acme-api",
            namespace="acme-payments",
            api_version="apps/v1",
            mode="get",
            workdir=tmp_path,
            context="ctx-two",
        )

    assert captured["context"] == "ctx-two"
