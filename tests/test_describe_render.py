from __future__ import annotations

from rwdiscovery.describe_render import render


def test_render_includes_identity_conditions_and_events():
    document = {
        "kind": "Deployment",
        "metadata": {
            "name": "acme-api",
            "namespace": "acme-payments",
            "creationTimestamp": "2026-09-01T00:00:00Z",
            "labels": {"app": "acme-api"},
        },
        "spec": {"replicas": 2},
    }
    status = {
        "conditions": [{"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable", "message": "ok"}]
    }
    events = [{"type": "Warning", "reason": "BackOff", "message": "boom", "lastTimestamp": "2026-09-24T00:00:00Z"}]
    text = render(
        document, status, events, "kubernetes/clusters/acme-prod-eu/namespaces/acme-payments/deployments/acme-api"
    )
    assert "Kind:        Deployment" in text
    assert "Name:        acme-api" in text
    assert "app=acme-api" in text
    assert "Available: True" in text
    assert "BackOff" in text


def test_render_handles_no_conditions_or_events():
    document = {"kind": "ConfigMap", "metadata": {"name": "acme-config"}}
    text = render(
        document, None, [], "kubernetes/clusters/acme-prod-eu/namespaces/acme-payments/configmaps/acme-config"
    )
    assert "<none>" in text
