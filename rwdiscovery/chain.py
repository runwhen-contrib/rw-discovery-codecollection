"""Kubernetes identity rules: type specs and the chain builder.

The split of responsibility is deliberate: papi decides *how* identity is
written down (the path/URN grammar, platform-contract §1), and this module
-- the discovery capability's own code -- decides *what* identifies a
Kubernetes object (the chain rules below). papi mints the path/URN from a
chain; this module only ever produces the chain -- it never builds a path
string itself. `path.py` carries a local, read-only mirror of papi's path
grammar, used only by the `inspect` task's human-facing output.

Rules implemented here:
  - root type is `cluster`, named by the `clusterName` input;
  - `namespace` -> `cluster`; every namespaced type -> `namespace`; every
    other cluster-scoped type -> `cluster`;
  - builtin kinds get fixed type names; legacy API groups for the same kind
    alias to the same type name (`extensions/Ingress` -> `ingress`);
  - anything not in the builtin table -- true CRDs, and any builtin kind we
    simply didn't enumerate -- is named `<kind lowercased>.<group>`, with
    plural `<plural>.<group>` (kubectl's own `resource.group` form);
  - `cluster` -> `clusters` is the one synthetic plural the pack declares by
    hand (there is no API resource named "cluster").
  - name case is `preserve` for every Kubernetes type (DNS-1123 names are
    already lowercase; RBAC/kubeconfig names can carry uppercase).

`packs/kubernetes/pack.yaml` ships the same table as data, registered with
papi. `tests/test_pack_yaml.py` cross-checks the two never drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple


@dataclass(frozen=True)
class TypeSpec:
    """One entry of platform-contract §2's `TypeSpec` shape, plus the local
    `groups` needed to resolve legacy API-group aliases back to this type."""

    type: str
    plural: str
    parent: str | None  # None only for the `cluster` root
    display_name: str
    category: str
    ephemeral: bool
    name_case: str  # "lower" | "preserve" -- Kubernetes always uses "preserve"
    aliases: tuple[str, ...] = ()
    native: dict[str, str] = field(default_factory=dict)  # {apiGroup, apiVersion, kind}


class ChainItem(NamedTuple):
    type: str
    name: str


# --- the two roots, declared by hand -----------------------------------------

CLUSTER = TypeSpec(
    type="cluster",
    plural="clusters",  # the one synthetic plural; there is no API resource named "cluster"
    parent=None,
    display_name="Cluster",
    category="cluster",
    ephemeral=False,
    name_case="preserve",
)

NAMESPACE = TypeSpec(
    type="namespace",
    plural="namespaces",
    parent="cluster",
    display_name="Namespace",
    category="core",
    ephemeral=False,
    name_case="preserve",
    aliases=("ns",),
    native={"apiGroup": "", "apiVersion": "v1", "kind": "Namespace"},
)


class _Def(NamedTuple):
    """One row of the builtin table below. `groups` lists every
    (apiGroup, apiVersion) this kind has ever lived under, oldest first --
    the last entry is canonical and feeds `native`. `kind` is the same
    across every group in practice (Kubernetes never renames a kind when it
    moves API groups)."""

    type: str
    plural: str
    parent: str  # "namespace" | "cluster"
    display_name: str
    category: str
    ephemeral: bool
    kind: str
    groups: tuple[tuple[str, str], ...]  # (apiGroup, apiVersion), "" = core
    aliases: tuple[str, ...] = ()


# The ephemeral denylist: dropped from storage, but pods,
# replicasets, endpointslices and events are still LISTED to feed rollups
# -- `ephemeral` here means "never pushed as an item", not "never
# read". Jobs owned by a CronJob are ephemeral too, but that is a per-object
# condition (an ownerReference), not a per-type one -- see enumerate.py's
# `is_ephemeral_instance`, which special-cases `job` on top of this table.
_BUILTINS: tuple[_Def, ...] = (
    # --- core/v1, namespaced -------------------------------------------------
    _Def("pod", "pods", "namespace", "Pod", "workload", True, "Pod", (("", "v1"),)),
    _Def("service", "services", "namespace", "Service", "network", False, "Service", (("", "v1"),), ("svc",)),
    _Def("endpoints", "endpoints", "namespace", "Endpoints", "network", True, "Endpoints", (("", "v1"),), ("ep",)),
    _Def("configmap", "configmaps", "namespace", "ConfigMap", "config", False, "ConfigMap", (("", "v1"),), ("cm",)),
    _Def("secret", "secrets", "namespace", "Secret", "config", False, "Secret", (("", "v1"),)),
    _Def(
        "serviceaccount",
        "serviceaccounts",
        "namespace",
        "ServiceAccount",
        "rbac",
        False,
        "ServiceAccount",
        (("", "v1"),),
        ("sa",),
    ),
    _Def(
        "persistentvolumeclaim",
        "persistentvolumeclaims",
        "namespace",
        "PersistentVolumeClaim",
        "storage",
        False,
        "PersistentVolumeClaim",
        (("", "v1"),),
        ("pvc",),
    ),
    _Def(
        "replicationcontroller",
        "replicationcontrollers",
        "namespace",
        "ReplicationController",
        "workload",
        False,
        "ReplicationController",
        (("", "v1"),),
        ("rc",),
    ),
    _Def(
        "limitrange",
        "limitranges",
        "namespace",
        "LimitRange",
        "policy",
        False,
        "LimitRange",
        (("", "v1"),),
        ("limits",),
    ),
    _Def(
        "resourcequota",
        "resourcequotas",
        "namespace",
        "ResourceQuota",
        "policy",
        False,
        "ResourceQuota",
        (("", "v1"),),
        ("quota",),
    ),
    _Def("event", "events", "namespace", "Event", "meta", True, "Event", (("", "v1"), ("events.k8s.io", "v1"))),
    # --- core/v1, cluster-scoped ---------------------------------------------
    _Def("node", "nodes", "cluster", "Node", "infra", False, "Node", (("", "v1"),), ("no",)),
    _Def(
        "persistentvolume",
        "persistentvolumes",
        "cluster",
        "PersistentVolume",
        "storage",
        False,
        "PersistentVolume",
        (("", "v1"),),
        ("pv",),
    ),
    _Def(
        "componentstatus",
        "componentstatuses",
        "cluster",
        "ComponentStatus",
        "meta",
        True,
        "ComponentStatus",
        (("", "v1"),),
        ("cs",),
    ),
    # --- apps/v1, namespaced --------------------------------------------------
    _Def(
        "deployment",
        "deployments",
        "namespace",
        "Deployment",
        "workload",
        False,
        "Deployment",
        (("extensions", "v1beta1"), ("apps", "v1")),
        ("deploy",),
    ),
    _Def(
        "statefulset",
        "statefulsets",
        "namespace",
        "StatefulSet",
        "workload",
        False,
        "StatefulSet",
        (("apps", "v1"),),
        ("sts",),
    ),
    _Def(
        "daemonset",
        "daemonsets",
        "namespace",
        "DaemonSet",
        "workload",
        False,
        "DaemonSet",
        (("extensions", "v1beta1"), ("apps", "v1")),
        ("ds",),
    ),
    _Def(
        "replicaset",
        "replicasets",
        "namespace",
        "ReplicaSet",
        "workload",
        True,
        "ReplicaSet",
        (("extensions", "v1beta1"), ("apps", "v1")),
        ("rs",),
    ),
    _Def(
        "controllerrevision",
        "controllerrevisions",
        "namespace",
        "ControllerRevision",
        "meta",
        True,
        "ControllerRevision",
        (("apps", "v1"),),
    ),
    # --- batch/v1, namespaced ---------------------------------------------
    # `job` is NOT globally ephemeral -- only instances owned by a CronJob
    # are (enumerate.py.is_ephemeral_instance). A standalone Job is a
    # first-class, storeable resource.
    _Def("job", "jobs", "namespace", "Job", "workload", False, "Job", (("batch", "v1"),)),
    _Def(
        "cronjob",
        "cronjobs",
        "namespace",
        "CronJob",
        "workload",
        False,
        "CronJob",
        (("batch", "v1beta1"), ("batch", "v1")),
        ("cj",),
    ),
    # --- networking.k8s.io, namespaced/cluster ------------------------------
    _Def(
        "ingress",
        "ingresses",
        "namespace",
        "Ingress",
        "network",
        False,
        "Ingress",
        (("extensions", "v1beta1"), ("networking.k8s.io", "v1")),
        ("ing",),
    ),
    _Def(
        "networkpolicy",
        "networkpolicies",
        "namespace",
        "NetworkPolicy",
        "network",
        False,
        "NetworkPolicy",
        (("extensions", "v1beta1"), ("networking.k8s.io", "v1")),
        ("netpol",),
    ),
    _Def(
        "ingressclass",
        "ingressclasses",
        "cluster",
        "IngressClass",
        "network",
        False,
        "IngressClass",
        (("networking.k8s.io", "v1"),),
    ),
    # --- discovery.k8s.io ----------------------------------------------------
    _Def(
        "endpointslice",
        "endpointslices",
        "namespace",
        "EndpointSlice",
        "network",
        True,
        "EndpointSlice",
        (("discovery.k8s.io", "v1"),),
    ),
    # --- rbac.authorization.k8s.io -------------------------------------------
    _Def("role", "roles", "namespace", "Role", "rbac", False, "Role", (("rbac.authorization.k8s.io", "v1"),)),
    _Def(
        "rolebinding",
        "rolebindings",
        "namespace",
        "RoleBinding",
        "rbac",
        False,
        "RoleBinding",
        (("rbac.authorization.k8s.io", "v1"),),
    ),
    _Def(
        "clusterrole",
        "clusterroles",
        "cluster",
        "ClusterRole",
        "rbac",
        False,
        "ClusterRole",
        (("rbac.authorization.k8s.io", "v1"),),
    ),
    _Def(
        "clusterrolebinding",
        "clusterrolebindings",
        "cluster",
        "ClusterRoleBinding",
        "rbac",
        False,
        "ClusterRoleBinding",
        (("rbac.authorization.k8s.io", "v1"),),
    ),
    # --- storage.k8s.io --------------------------------------------------
    _Def(
        "storageclass",
        "storageclasses",
        "cluster",
        "StorageClass",
        "storage",
        False,
        "StorageClass",
        (("storage.k8s.io", "v1"),),
        ("sc",),
    ),
    _Def(
        "volumeattachment",
        "volumeattachments",
        "cluster",
        "VolumeAttachment",
        "storage",
        False,
        "VolumeAttachment",
        (("storage.k8s.io", "v1"),),
    ),
    _Def("csidriver", "csidrivers", "cluster", "CSIDriver", "storage", False, "CSIDriver", (("storage.k8s.io", "v1"),)),
    _Def("csinode", "csinodes", "cluster", "CSINode", "storage", False, "CSINode", (("storage.k8s.io", "v1"),)),
    # --- policy ---------------------------------------------------------------
    _Def(
        "poddisruptionbudget",
        "poddisruptionbudgets",
        "namespace",
        "PodDisruptionBudget",
        "policy",
        False,
        "PodDisruptionBudget",
        (("policy", "v1beta1"), ("policy", "v1")),
        ("pdb",),
    ),
    # --- autoscaling ------------------------------------------------------
    _Def(
        "horizontalpodautoscaler",
        "horizontalpodautoscalers",
        "namespace",
        "HorizontalPodAutoscaler",
        "workload",
        False,
        "HorizontalPodAutoscaler",
        (("autoscaling", "v1"), ("autoscaling", "v2")),
        ("hpa",),
    ),
    # --- coordination.k8s.io (leader-election leases; ephemeral) -----------
    _Def("lease", "leases", "namespace", "Lease", "meta", True, "Lease", (("coordination.k8s.io", "v1"),)),
    # --- scheduling.k8s.io ---------------------------------------------------
    _Def(
        "priorityclass",
        "priorityclasses",
        "cluster",
        "PriorityClass",
        "policy",
        False,
        "PriorityClass",
        (("scheduling.k8s.io", "v1"),),
        ("pc",),
    ),
    # --- admissionregistration.k8s.io ----------------------------------------
    _Def(
        "validatingwebhookconfiguration",
        "validatingwebhookconfigurations",
        "cluster",
        "ValidatingWebhookConfiguration",
        "meta",
        False,
        "ValidatingWebhookConfiguration",
        (("admissionregistration.k8s.io", "v1"),),
    ),
    _Def(
        "mutatingwebhookconfiguration",
        "mutatingwebhookconfigurations",
        "cluster",
        "MutatingWebhookConfiguration",
        "meta",
        False,
        "MutatingWebhookConfiguration",
        (("admissionregistration.k8s.io", "v1"),),
    ),
    # --- node.k8s.io -----------------------------------------------------
    _Def(
        "runtimeclass",
        "runtimeclasses",
        "cluster",
        "RuntimeClass",
        "infra",
        False,
        "RuntimeClass",
        (("node.k8s.io", "v1"),),
    ),
    # --- apiextensions.k8s.io ----------------------------------------------
    _Def(
        "customresourcedefinition",
        "customresourcedefinitions",
        "cluster",
        "CustomResourceDefinition",
        "meta",
        False,
        "CustomResourceDefinition",
        (("apiextensions.k8s.io", "v1"),),
        ("crd", "crds"),
    ),
    # --- certificates.k8s.io -------------------------------------------------
    _Def(
        "certificatesigningrequest",
        "certificatesigningrequests",
        "cluster",
        "CertificateSigningRequest",
        "security",
        False,
        "CertificateSigningRequest",
        (("certificates.k8s.io", "v1"),),
        ("csr",),
    ),
)


def _build_lookup() -> dict[tuple[str, str], TypeSpec]:
    lookup: dict[tuple[str, str], TypeSpec] = {}
    for d in _BUILTINS:
        group, version = d.groups[-1]
        native = {"apiGroup": group, "apiVersion": version, "kind": d.kind}
        spec = TypeSpec(
            type=d.type,
            plural=d.plural,
            parent=d.parent,
            display_name=d.display_name,
            category=d.category,
            ephemeral=d.ephemeral,
            name_case="preserve",
            aliases=d.aliases,
            native=native,
        )
        for group, _version in d.groups:
            lookup[(group, d.kind)] = spec
    return lookup


BUILTIN_TYPES: dict[tuple[str, str], TypeSpec] = _build_lookup()

# Denylist patterns that are not exact (group, kind) pairs: "*reviews" and
# "metrics.k8s.io/*". Matched by kind suffix / group,
# independent of the builtin table (these kinds are rarely, if ever, listed
# at all -- most clusters return 403/405 for them -- but if API discovery
# does surface one, it must never be pushed).
_EPHEMERAL_KIND_SUFFIXES = ("Review",)
_EPHEMERAL_GROUPS = ("metrics.k8s.io",)
# Well-known ephemeral CRD kinds: cert-manager's
# per-issuance objects, created and garbage-collected on every renewal.
_EPHEMERAL_CRD_KINDS = frozenset(
    {
        ("acme.cert-manager.io", "Order"),
        ("acme.cert-manager.io", "Challenge"),
        ("cert-manager.io", "CertificateRequest"),
    }
)


def is_ephemeral_type(group: str, kind: str, spec: TypeSpec | None = None) -> bool:
    if spec is not None and spec.ephemeral:
        return True
    if group in _EPHEMERAL_GROUPS or (group, kind) in _EPHEMERAL_CRD_KINDS:
        return True
    return any(kind.endswith(suffix) for suffix in _EPHEMERAL_KIND_SUFFIXES)


def resolve_type(
    group: str,
    version: str,
    kind: str,
    api_plural: str,
    namespaced: bool,
) -> TypeSpec:
    """Resolves an API resource (as returned by discovery, or read off an
    object's own apiVersion/kind) to its TypeSpec. Builtins first; anything
    else -- a true CRD, or a builtin kind this table doesn't enumerate --
    falls back to the generic `<kind>.<group>` rule."""
    if not group and kind == "Namespace":
        return NAMESPACE
    spec = BUILTIN_TYPES.get((group, kind))
    if spec is not None:
        return spec
    if group:
        type_name = f"{kind.lower()}.{group}"
        plural = f"{api_plural}.{group}"
    else:
        type_name = kind.lower()
        plural = api_plural
    return TypeSpec(
        type=type_name,
        plural=plural,
        parent="namespace" if namespaced else "cluster",
        display_name=kind,
        category="custom" if group else "core",
        ephemeral=False,
        name_case="preserve",
        aliases=(),
        native={"apiGroup": group, "apiVersion": f"{group}/{version}" if group else version, "kind": kind},
    )


def build_chain(cluster_name: str, spec: TypeSpec, name: str, namespace: str | None) -> list[ChainItem]:
    """The typed containment chain for one object -- cluster, [namespace],
    self. papi is the sole minter of the path/URN (platform-contract §1);
    this function never builds a path string itself."""
    chain = [ChainItem("cluster", cluster_name)]
    if spec.parent == "namespace":
        if not namespace:
            raise ValueError(f"type {spec.type!r} is namespaced but no namespace was given")
        chain.append(ChainItem("namespace", namespace))
    chain.append(ChainItem(spec.type, name))
    return chain


def cluster_chain(cluster_name: str) -> list[ChainItem]:
    return [ChainItem("cluster", cluster_name)]


def namespace_chain(cluster_name: str, namespace: str) -> list[ChainItem]:
    return [ChainItem("cluster", cluster_name), ChainItem("namespace", namespace)]


def parse_api_version(api_version: str) -> tuple[str, str]:
    """`"apps/v1"` -> `("apps", "v1")`; `"v1"` -> `("", "v1")`."""
    if "/" in api_version:
        group, version = api_version.split("/", 1)
        return group, version
    return "", api_version


def chain_for_object(cluster_name: str, obj: dict, plural_hint: str | None = None) -> tuple[list[ChainItem], TypeSpec]:
    """Convenience wrapper reading `apiVersion`/`kind`/`metadata` straight
    off a raw object -- what `discover.py` and `inspect.py` call per item,
    and what `tests/test_chain_vectors.py` drives from
    `packs/kubernetes/vectors/chain_vectors.json`.

    `plural_hint` should be the real API plural from discovery whenever the
    caller has it (`discover.py` always does -- it comes from the same
    `ApiResource` the object was listed under). Without one, this falls
    back to a naive `<kind>s` guess, which is wrong for irregular plurals
    (`GatewayClass` -> `gatewayclasss`, not `gatewayclasses`) -- fine for a
    type this table already knows (the guess is only used for the type
    *name*, `<kind>.<group>`, never for that fallback's plural segment
    unless no better information exists) but never the right source of
    truth when a precise plural is available."""
    group, version = parse_api_version(obj.get("apiVersion", ""))
    kind = obj.get("kind", "")
    metadata = obj.get("metadata") or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name", "")
    plural = plural_hint or f"{kind.lower()}s"
    spec = resolve_type(group, version, kind, plural, namespaced=namespace is not None)
    chain = build_chain(cluster_name, spec, name, namespace)
    return chain, spec
