from __future__ import annotations

from rwdiscovery.chain import (
    CLUSTER,
    NAMESPACE,
    ChainItem,
    build_chain,
    cluster_chain,
    is_ephemeral_type,
    namespace_chain,
    resolve_type,
)


def test_builtin_deployment_resolves_by_canonical_group():
    spec = resolve_type("apps", "v1", "Deployment", "deployments", namespaced=True)
    assert spec.type == "deployment"
    assert spec.plural == "deployments"
    assert spec.parent == "namespace"
    assert spec.aliases == ("deploy",)


def test_legacy_ingress_group_aliases_to_same_type_as_current_group():
    legacy = resolve_type("extensions", "v1beta1", "Ingress", "ingresses", namespaced=True)
    current = resolve_type("networking.k8s.io", "v1", "Ingress", "ingresses", namespaced=True)
    assert legacy.type == current.type == "ingress"
    # native reflects the canonical (most recent) group, not the legacy one
    assert current.native["apiGroup"] == "networking.k8s.io"


def test_namespace_object_resolves_to_the_namespace_root_type():
    spec = resolve_type("", "v1", "Namespace", "namespaces", namespaced=False)
    assert spec is NAMESPACE


def test_unknown_crd_falls_back_to_kind_dot_group():
    spec = resolve_type("cert-manager.io", "v1", "Certificate", "certificates", namespaced=True)
    assert spec.type == "certificate.cert-manager.io"
    assert spec.plural == "certificates.cert-manager.io"
    assert spec.parent == "namespace"


def test_unknown_cluster_scoped_crd_falls_back_to_kind_dot_group():
    spec = resolve_type("cert-manager.io", "v1", "ClusterIssuer", "clusterissuers", namespaced=False)
    assert spec.type == "clusterissuer.cert-manager.io"
    assert spec.parent == "cluster"


def test_build_chain_for_namespaced_type():
    spec = resolve_type("apps", "v1", "Deployment", "deployments", namespaced=True)
    chain = build_chain("acme-prod-eu", spec, "api", "acme-payments")
    assert chain == [
        ChainItem("cluster", "acme-prod-eu"),
        ChainItem("namespace", "acme-payments"),
        ChainItem("deployment", "api"),
    ]


def test_build_chain_for_cluster_scoped_type():
    spec = resolve_type("rbac.authorization.k8s.io", "v1", "ClusterRole", "clusterroles", namespaced=False)
    chain = build_chain("acme-prod-eu", spec, "system:controller:job-controller", None)
    assert chain == [
        ChainItem("cluster", "acme-prod-eu"),
        ChainItem("clusterrole", "system:controller:job-controller"),
    ]


def test_build_chain_requires_namespace_for_namespaced_type():
    spec = resolve_type("apps", "v1", "Deployment", "deployments", namespaced=True)
    try:
        build_chain("acme-prod-eu", spec, "api", None)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for missing namespace")


def test_cluster_and_namespace_chain_helpers():
    assert cluster_chain("acme-prod-eu") == [ChainItem("cluster", "acme-prod-eu")]
    assert namespace_chain("acme-prod-eu", "acme-payments") == [
        ChainItem("cluster", "acme-prod-eu"),
        ChainItem("namespace", "acme-payments"),
    ]


def test_cluster_root_has_no_parent():
    assert CLUSTER.parent is None


def test_ephemeral_denylist_types():
    pod = resolve_type("", "v1", "Pod", "pods", namespaced=True)
    service = resolve_type("", "v1", "Service", "services", namespaced=True)
    assert is_ephemeral_type("", "Pod", pod) is True
    assert is_ephemeral_type("", "Service", service) is False


def test_ephemeral_review_suffix_and_metrics_group():
    fake_review = resolve_type(
        "authorization.k8s.io", "v1", "SubjectAccessReview", "subjectaccessreviews", namespaced=False
    )
    fake_metrics = resolve_type("metrics.k8s.io", "v1beta1", "PodMetrics", "pods", namespaced=True)
    assert is_ephemeral_type("authorization.k8s.io", "SubjectAccessReview", fake_review) is True
    assert is_ephemeral_type("metrics.k8s.io", "PodMetrics", fake_metrics) is True


def test_job_type_itself_is_not_globally_ephemeral():
    """Only jobs OWNED BY a CronJob are ephemeral -- a per-object condition
    enumerate.py checks, not a type-level flag."""
    job = resolve_type("batch", "v1", "Job", "jobs", namespaced=True)
    assert job.ephemeral is False


def test_cert_manager_issuance_kinds_are_ephemeral():
    """cert-manager's own per-issuance orders/challenges/certificaterequests are ephemeral."""
    assert is_ephemeral_type("acme.cert-manager.io", "Order") is True
    assert is_ephemeral_type("acme.cert-manager.io", "Challenge") is True
    assert is_ephemeral_type("cert-manager.io", "CertificateRequest") is True
    assert is_ephemeral_type("cert-manager.io", "Certificate") is False
