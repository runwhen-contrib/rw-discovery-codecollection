"""path.py mirrors papi's grammar (platform-contract §1) -- these vectors are
taken directly from that grammar's own worked examples, so a drift in either place is
caught here."""

from __future__ import annotations

from rwdiscovery.chain import CLUSTER, NAMESPACE, ChainItem, resolve_type
from rwdiscovery.path import build_path, enc


def _specs(*types):
    return {t.type: t for t in types}


def test_enc_percent_encodes_colon_and_preserves_case():
    assert enc("system:controller:job-controller") == "system%3Acontroller%3Ajob-controller"


def test_enc_lower_name_case():
    assert enc("ACME-Repo", name_case="lower") == "acme-repo"


def test_enc_passes_through_ordinary_characters():
    assert enc("api-7d9f") == "api-7d9f"


def test_deployment_path_matches_design_table():
    deployment = resolve_type("apps", "v1", "Deployment", "deployments", namespaced=True)
    chain = [ChainItem("cluster", "prod-eu"), ChainItem("namespace", "payments"), ChainItem("deployment", "api")]
    path = build_path("kubernetes", chain, _specs(CLUSTER, NAMESPACE, deployment))
    assert path == "kubernetes/clusters/prod-eu/namespaces/payments/deployments/api"


def test_clusterrole_with_colon_is_percent_encoded():
    clusterrole = resolve_type("rbac.authorization.k8s.io", "v1", "ClusterRole", "clusterroles", namespaced=False)
    chain = [ChainItem("cluster", "prod-eu"), ChainItem("clusterrole", "system:controller:job-controller")]
    path = build_path("kubernetes", chain, _specs(CLUSTER, clusterrole))
    assert path == "kubernetes/clusters/prod-eu/clusterroles/system%3Acontroller%3Ajob-controller"


def test_crd_path_uses_kind_dot_group_plural():
    certificate = resolve_type("cert-manager.io", "v1", "Certificate", "certificates", namespaced=True)
    chain = [
        ChainItem("cluster", "prod-eu"),
        ChainItem("namespace", "payments"),
        ChainItem("certificate.cert-manager.io", "api-tls"),
    ]
    path = build_path("kubernetes", chain, _specs(CLUSTER, NAMESPACE, certificate))
    assert path == "kubernetes/clusters/prod-eu/namespaces/payments/certificates.cert-manager.io/api-tls"


def test_arn_cluster_name_is_percent_encoded():
    chain = [ChainItem("cluster", "arn:aws:eks:eu-west-1:123:cluster/prod")]
    path = build_path("kubernetes", chain, _specs(CLUSTER))
    assert path == "kubernetes/clusters/arn%3Aaws%3Aeks%3Aeu-west-1%3A123%3Acluster%2Fprod"


def test_pod_path_computable_even_though_never_stored():
    pod = resolve_type("", "v1", "Pod", "pods", namespaced=True)
    chain = [ChainItem("cluster", "prod-eu"), ChainItem("namespace", "payments"), ChainItem("pod", "api-7d9f-x2")]
    path = build_path("kubernetes", chain, _specs(CLUSTER, NAMESPACE, pod))
    assert path == "kubernetes/clusters/prod-eu/namespaces/payments/pods/api-7d9f-x2"
