from __future__ import annotations

from rwdiscovery.enumerate import discover_resources, is_job_owned_by_cronjob
from tests.fakes import FakeK8sClient


def test_discover_resources_keeps_only_list_verb_and_drops_subresources():
    fake = FakeK8sClient(
        single={
            "/api/v1": {
                "resources": [
                    {"name": "pods", "kind": "Pod", "namespaced": True, "verbs": ["get", "list", "watch"]},
                    {"name": "pods/log", "kind": "PodLog", "namespaced": True, "verbs": ["get"]},
                    {"name": "bindings", "kind": "Binding", "namespaced": True, "verbs": ["create"]},
                ]
            },
            "/apis": {"groups": []},
        }
    )
    resources = discover_resources(fake)
    names = {r.plural for r in resources}
    assert names == {"pods"}


def test_discover_resources_covers_preferred_group_version_and_crds():
    fake = FakeK8sClient(
        single={
            "/api/v1": {"resources": []},
            "/apis": {
                "groups": [
                    {
                        "name": "apps",
                        "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
                        "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                    },
                    {
                        "name": "cert-manager.io",
                        "preferredVersion": {"groupVersion": "cert-manager.io/v1", "version": "v1"},
                        "versions": [{"groupVersion": "cert-manager.io/v1", "version": "v1"}],
                    },
                ]
            },
            "/apis/apps/v1": {
                "resources": [
                    {"name": "deployments", "kind": "Deployment", "namespaced": True, "verbs": ["get", "list"]}
                ]
            },
            "/apis/cert-manager.io/v1": {
                "resources": [
                    {
                        "name": "certificates",
                        "kind": "Certificate",
                        "namespaced": True,
                        "verbs": ["get", "list"],
                    }
                ]
            },
        }
    )
    resources = discover_resources(fake)
    by_plural = {r.plural: r for r in resources}
    assert by_plural["deployments"].type_spec.type == "deployment"
    assert by_plural["certificates"].type_spec.type == "certificate.cert-manager.io"


def test_discover_resources_skips_unreadable_group():
    fake = FakeK8sClient(
        single={
            "/api/v1": {"resources": []},
            "/apis": {
                "groups": [
                    {
                        "name": "metrics.k8s.io",
                        "preferredVersion": {"groupVersion": "metrics.k8s.io/v1beta1", "version": "v1beta1"},
                        "versions": [{"groupVersion": "metrics.k8s.io/v1beta1", "version": "v1beta1"}],
                    }
                ]
            },
            # deliberately no "/apis/metrics.k8s.io/v1beta1" entry -> 404 in the fake
        }
    )
    resources = discover_resources(fake)
    assert resources == []


def test_discover_resources_dedupes_legacy_group_alias_preferring_non_legacy():
    """`extensions` (listed first, as it would sort alphabetically before
    "networking.k8s.io") and the modern group both serve Ingress on an old
    enough cluster -- `resolve_type` maps both to the same `ingress` type,
    so discovery must return exactly one ApiResource for it, from the
    non-legacy group, not two (which would list/push every Ingress twice
    and emit two commit partitions for the same type)."""
    fake = FakeK8sClient(
        single={
            "/api/v1": {"resources": []},
            "/apis": {
                "groups": [
                    {
                        "name": "extensions",
                        "preferredVersion": {"groupVersion": "extensions/v1beta1", "version": "v1beta1"},
                        "versions": [{"groupVersion": "extensions/v1beta1", "version": "v1beta1"}],
                    },
                    {
                        "name": "networking.k8s.io",
                        "preferredVersion": {"groupVersion": "networking.k8s.io/v1", "version": "v1"},
                        "versions": [{"groupVersion": "networking.k8s.io/v1", "version": "v1"}],
                    },
                ]
            },
            "/apis/extensions/v1beta1": {
                "resources": [{"name": "ingresses", "kind": "Ingress", "namespaced": True, "verbs": ["get", "list"]}]
            },
            "/apis/networking.k8s.io/v1": {
                "resources": [{"name": "ingresses", "kind": "Ingress", "namespaced": True, "verbs": ["get", "list"]}]
            },
        }
    )
    resources = discover_resources(fake)
    ingress_resources = [r for r in resources if r.type_spec.type == "ingress"]
    assert len(ingress_resources) == 1
    assert ingress_resources[0].group == "networking.k8s.io"


def test_is_job_owned_by_cronjob():
    owned = {"metadata": {"ownerReferences": [{"kind": "CronJob", "name": "acme-nightly"}]}}
    standalone = {"metadata": {}}
    assert is_job_owned_by_cronjob(owned) is True
    assert is_job_owned_by_cronjob(standalone) is False
