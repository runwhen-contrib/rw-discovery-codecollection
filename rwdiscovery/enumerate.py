"""API enumeration: walks `/api` and `/apis` preferred versions and keeps
the types whose verbs include `list` -- the same set `kubectl
api-resources --verbs=list` shows, so every CRD is included automatically.
"""

from __future__ import annotations

from dataclasses import dataclass

from .chain import TypeSpec, is_ephemeral_type, resolve_type
from .k8s_client import K8sClient


@dataclass(frozen=True)
class ApiResource:
    group: str
    version: str
    kind: str
    plural: str
    namespaced: bool
    verbs: tuple[str, ...]
    type_spec: TypeSpec
    ephemeral: bool


def resources_from_list(group: str, version: str, body: dict) -> list[ApiResource]:
    """Public so `inspect.py` can resolve one (kind, apiVersion) directly
    against a single group's discovery document, instead of paying for a
    full `discover_resources()` sweep just to find one kind."""
    out: list[ApiResource] = []
    for r in body.get("resources", []):
        name = r.get("name", "")
        if "/" in name:
            continue  # subresources (pods/log, deployments/scale, ...) are never listed themselves
        verbs = tuple(r.get("verbs", []))
        if "list" not in verbs:
            continue
        kind = r.get("kind", "")
        namespaced = bool(r.get("namespaced", False))
        spec = resolve_type(group, version, kind, name, namespaced)
        out.append(
            ApiResource(
                group=group,
                version=version,
                kind=kind,
                plural=name,
                namespaced=namespaced,
                verbs=verbs,
                type_spec=spec,
                ephemeral=is_ephemeral_type(group, kind, spec),
            )
        )
    return out


# A group Kubernetes has fully retired in favor of a newer one -- `extensions`
# is the one that matters in practice (Ingress/NetworkPolicy/DaemonSet/
# Deployment/ReplicaSet all lived there once; chain.py's builtin table
# aliases every one of them to its modern group). A cluster old enough (or
# running a compatibility shim) can still serve BOTH groups for the same
# kind at once; see `_dedupe_by_type`'s docstring for why that matters here.
_LEGACY_GROUPS = frozenset({"extensions"})


def _dedupe_by_type(resources: list[ApiResource]) -> list[ApiResource]:
    """The same kind can be served under more than one API group at once --
    most often a legacy group Kubernetes hasn't fully retired alongside its
    replacement. `resolve_type` maps every alias group to the identical
    TypeSpec (chain.py's builtin `groups` table), so without this,
    `discover_resources` would return TWO `ApiResource`s for the same
    logical type; `discover.py` would then list and push every such
    object twice and emit two commit partitions for one `(type,
    parentPath)` (platform-contract §3 expects exactly one). Keep exactly
    one resource per resolved type -- the non-legacy group wins even when
    a legacy group like `extensions` would otherwise win by being listed
    first (`/apis` groups are typically returned alphabetically, and
    "extensions" sorts before most modern group names)."""
    by_type: dict[str, ApiResource] = {}
    for resource in resources:
        type_name = resource.type_spec.type
        current = by_type.get(type_name)
        if current is None or (current.group in _LEGACY_GROUPS and resource.group not in _LEGACY_GROUPS):
            by_type[type_name] = resource
    return list(by_type.values())


def discover_resources(k8s: K8sClient) -> list[ApiResource]:
    """Every listable resource: core/v1, plus every API group's preferred
    version. A group whose preferred version can't be read (a rare RBAC
    gap on the discovery document itself, or a group in a transient state)
    is skipped rather than failing the whole enumeration. Deduped by
    resolved type afterwards -- see `_dedupe_by_type`."""
    resources: list[ApiResource] = []

    core = k8s.get_raw("/api/v1")
    resources.extend(resources_from_list("", "v1", core))

    groups = k8s.get_raw("/apis")
    for group in groups.get("groups", []):
        preferred = group.get("preferredVersion") or next(iter(group.get("versions", [])), None)
        if not preferred:
            continue
        group_name = group["name"]
        version = preferred["version"]
        try:
            group_resources = k8s.get_raw(f"/apis/{group_name}/{version}")
        except Exception:  # noqa: BLE001 -- one unreadable group must not abort discovery
            continue
        resources.extend(resources_from_list(group_name, version, group_resources))

    return _dedupe_by_type(resources)


def is_job_owned_by_cronjob(item: dict) -> bool:
    """The one ephemeral condition that is per-object rather than
    per-type: a standalone Job is a first-class resource,
    but one a CronJob spawned is not."""
    for ref in (item.get("metadata") or {}).get("ownerReferences") or []:
        if ref.get("kind") == "CronJob":
            return True
    return False
