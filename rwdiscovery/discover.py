"""The `discover` task's orchestration (platform-contract §3/§5). Thin
building blocks (`chain.py`, `sanitize.py`, `rollups.py`,
`paginate.py`, `sync.py`, `packbuild.py`) do the real work; this module
only wires them in the right order:

  1. register the pack (idempotent by digest);
  2. open the sync;
  3. push the cluster item, then in-scope namespace items, then everything
     else -- cluster -> namespaces -> rest;
  4. commit with one partition per (type, parentPath) listed;
  5. return the summary result (`rw.discovery_summary.v1`).

Any exception after step 2 -- including a failed commit -- aborts the open
sync (never leaves it dangling for the 45-minute lease to expire on its
own; the abort itself is best-effort, so it can never mask the original
error) and re-raises --
`tasks.py`'s task function lets it propagate, and the SDK's host turns it
into a failed TaskResult (never a silently-empty summary).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import credentials
from .chain import NAMESPACE, ChainItem, build_chain, cluster_chain
from .connect import read_cluster_uid
from .enumerate import ApiResource, discover_resources, is_job_owned_by_cronjob
from .k8s_client import ApiError, ForbiddenError, K8sClient, path_segment
from .k8s_client import resource_path as api_resource_path
from .packbuild import build_pack_payload
from .paginate import PageEvent, Partition, PartitionEvent, iter_pages, list_resource
from .rollup_context import ROLLUP_SOURCE_TYPES, NamespaceRollupContext
from .rollups import k8s_cluster_rollup
from .sanitize import SanitizeOptions, sanitize
from .sync import BatchingPusher, ResourceSyncCredential, SyncClient

PLATFORM = "kubernetes"
SOURCE = "k8s-discovery"

CRD_LIST_PATH = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"
NODES_PATH = "/api/v1/nodes"
API_GROUPS_PATH = "/apis"

# The summary's `rollupSourcesUnavailable` key for sources read once per
# cluster (currently just `node`, for `k8sCluster`) rather than once per
# namespace -- every other key in that map is a namespace name.
CLUSTER_SCOPE_KEY = ""
# Bounded so a cluster with many forbidden namespaces can't bloat the
# summary envelope; sorted so which namespaces survive the cap is at least
# deterministic.
MAX_ROLLUP_SOURCES_UNAVAILABLE_ENTRIES = 50


def scope_path_for(cluster_name: str) -> str:
    return f"kubernetes/clusters/{cluster_name}"


def _identity(platform: str, chain: list[ChainItem]) -> dict:
    return {"platform": platform, "chain": [{"type": c.type, "name": c.name} for c in chain]}


def _build_item(
    cluster_name: str,
    spec_chain: list[ChainItem],
    raw_obj: dict,
    sanitize_options: SanitizeOptions,
    rollups: dict | None = None,
) -> dict:
    metadata = raw_obj.get("metadata") or {}
    document, status = sanitize(raw_obj, sanitize_options)
    item: dict = {
        "identity": _identity(PLATFORM, spec_chain),
        # From the sanitized document, not the raw object: every field that
        # leaves the cluster goes through sanitize.py.
        "labels": (document.get("metadata") or {}).get("labels") or {},
        "document": document,
    }
    if metadata.get("uid"):
        item["providerUid"] = metadata["uid"]
    display_name = metadata.get("name")
    if display_name:
        item["displayName"] = display_name
    if status is not None:
        item["status"] = status
    if rollups:
        item["rollups"] = rollups
    return item


def _list_best_effort(
    k8s: K8sClient, path: str, project: Callable[[dict], dict] | None = None
) -> tuple[list[dict], str | None]:
    """Used for auxiliary, non-authoritative reads (CRDs for pretty
    printer-column facets, rollup source collections): a 403/error here
    degrades gracefully rather than failing the whole run, since none of
    these feed the sync's own partitions/sweep. Follows `continue` tokens
    (a single `limit=500` page silently truncated rollups and dropped every
    CRD past the 500th from the pack). `project` shrinks each item as its
    page arrives, so only what the caller needs is ever held.

    Returns `(items, unavailable)`: `unavailable` is `None` on success, or
    `"forbidden"`/`"failed"` when the listing itself couldn't be read --
    callers that feed a rollup (unlike CRD listing, whose only use is the
    additive pack's printer-column summaries) must tell it apart from a
    genuine empty list, since a rollup built from `[]` here would otherwise
    be indistinguishable from a confirmed zero (see `rollup_context.py`)."""
    items: list[dict] = []
    try:
        for page in iter_pages(k8s, path):
            items.extend(map(project, page) if project else page)
    except ForbiddenError:
        return [], "forbidden"
    except ApiError:
        return [], "failed"
    return items, None


def _crd_essentials(crd: dict) -> dict:
    """The fields `packbuild.crd_type_specs_and_summaries` reads. A full CRD
    carries its whole OpenAPI schema (often hundreds of KB), and clusters
    with 1000+ CRDs exist (Crossplane providers)."""
    spec = crd.get("spec") or {}
    return {
        "spec": {
            **{k: spec[k] for k in ("group", "names", "scope") if k in spec},
            "versions": [
                {k: v.get(k) for k in ("name", "storage", "additionalPrinterColumns")}
                for v in spec.get("versions") or []
            ],
        }
    }


@dataclass
class _Counters:
    partitions: list[Partition] = field(default_factory=list)
    partition_types: list[str] = field(default_factory=list)  # parallel to `partitions`
    # Namespace name (or `CLUSTER_SCOPE_KEY` for the cluster-scoped `node`
    # source) -> the rollup source types that were unavailable there this
    # run -- feeds the summary's `rollupSourcesUnavailable`.
    rollup_sources_unavailable: dict[str, list[str]] = field(default_factory=dict)


def run_discover(
    *,
    kubeconfig_yaml: str,
    resource_sync_raw: str,
    cluster_name: str,
    namespaces: list[str] | None,
    exclude_namespaces: list[str] | None,
    config_map_values: str,
    overlay: dict | None,
    workdir: Path,
    capability_run_uuid: str | None = None,
    k8s_client: K8sClient | None = None,
) -> dict:
    """`k8s_client` is a test seam only -- `tasks.py` never passes it, so
    production always materialises a fresh client from the `kubeconfig`
    credential (`credentials.build_api_client`); tests inject a fake
    `K8sClient` (see `tests/fakes.py`) instead of a real cluster."""
    started = time.monotonic()
    k8s = k8s_client or K8sClient(credentials.build_api_client(kubeconfig_yaml, workdir))
    sanitize_options = SanitizeOptions(
        config_map_values=config_map_values or "store",
        extra_redactions=(overlay or {}).get("redactions", []),
    )

    version_info = k8s.get_raw("/version")
    server_version = version_info.get("gitVersion", "")
    cluster_uid = read_cluster_uid(k8s)

    sync_client = SyncClient(credential=ResourceSyncCredential.parse(resource_sync_raw))

    crds, _crds_unavailable = _list_best_effort(k8s, CRD_LIST_PATH, project=_crd_essentials)
    # One discovery sweep, reused for both pack registration (every listable
    # type needs a registered TypeSpec, not just builtins + CRDs -- see
    # packbuild.extra_discovered_type_specs) and the item push below.
    resources = discover_resources(k8s)
    pack_payload = build_pack_payload(discovered_crds=crds, discovered_resources=resources)
    pack_result = sync_client.put_pack(pack_payload) or {}
    # papi's canonical digest is authoritative; fall back to ours only if it
    # didn't return one.
    pack_digest = pack_result.get("digest") or pack_payload["digest"]

    scope_path = scope_path_for(cluster_name)
    open_result = sync_client.open_sync(
        source=SOURCE,
        scope_path=scope_path,
        capability_run_uuid=capability_run_uuid,
        pack={"name": pack_payload["name"], "digest": pack_digest},
    )
    sync_id = open_result["syncId"]
    pusher = BatchingPusher(client=sync_client, sync_id=sync_id)
    counters = _Counters()

    try:
        all_ns_items, ns_list_failure = _list_namespaces(k8s)
        in_scope_namespaces = _resolve_in_scope_namespaces(all_ns_items, namespaces, exclude_namespaces)
        _push_cluster_and_namespaces(
            k8s,
            cluster_name,
            cluster_uid,
            all_ns_items,
            ns_list_failure,
            in_scope_namespaces,
            version_info,
            sanitize_options,
            pusher,
            counters,
        )
        _push_everything_else(k8s, cluster_name, resources, in_scope_namespaces, sanitize_options, pusher, counters)
        pusher.flush()

        commit_body = [
            _commit_partition_entry(cluster_name, partition_type, partition, pusher.rejected_partitions)
            for partition_type, partition in zip(counters.partition_types, counters.partitions, strict=True)
        ]
        commit_result = sync_client.commit(sync_id, commit_body)
    except Exception as exc:  # noqa: BLE001 -- any failure here must abort the open sync, never leave it dangling
        try:
            sync_client.abort(sync_id, str(exc)[:500])
        except Exception:  # noqa: BLE001 -- best effort; papi's own run-failure hook aborts it too (platform-contract §3)
            pass
        raise

    status_counts = {"complete": 0, "failed": 0, "forbidden": 0}
    for partition in counters.partitions:
        status_counts[partition.status] = status_counts.get(partition.status, 0) + 1

    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "syncId": sync_id,
        "packDigest": pack_digest,
        "counts": commit_result.get(
            "counts",
            {
                "created": pusher.totals.get("created", 0),
                "updated": pusher.totals.get("updated", 0),
                "unchanged": pusher.totals.get("unchanged", 0),
                "deleted": 0,
                "held": 0,
            },
        ),
        "partitions": status_counts,
        "durationMs": duration_ms,
        "serverVersion": server_version,
        "clusterUid": cluster_uid,
        "rollupSourcesUnavailable": _capped_rollup_sources_unavailable(counters.rollup_sources_unavailable),
    }


def _capped_rollup_sources_unavailable(by_scope: dict[str, list[str]]) -> dict[str, list[str]]:
    """Bounds the summary's `rollupSourcesUnavailable` (namespace name, or
    `CLUSTER_SCOPE_KEY` for the cluster scope -> unavailable source types)
    so a cluster with many forbidden namespaces can't bloat the envelope."""
    if len(by_scope) <= MAX_ROLLUP_SOURCES_UNAVAILABLE_ENTRIES:
        return by_scope
    return dict(sorted(by_scope.items())[:MAX_ROLLUP_SOURCES_UNAVAILABLE_ENTRIES])


def _partition_parent_path(cluster_name: str, partition: Partition) -> str:
    if partition.namespace is None:
        return scope_path_for(cluster_name)
    return f"{scope_path_for(cluster_name)}/namespaces/{partition.namespace}"


def _commit_partition_entry(
    cluster_name: str,
    partition_type: str,
    partition: Partition,
    rejected_partitions: dict[tuple[str, str | None], set[str]],
) -> dict:
    """platform-contract §3: any `(type, parentPath)` that
    had at least one item rejected on the way in is reported `failed` at
    commit -- never `complete` -- so it is never swept, even though every
    OTHER item pushed for it landed fine. `failed`/`forbidden` partitions
    are left as they are: they are already never-swept, and a rejection
    reason wouldn't add information a caller (SyncClientError, a listing
    403) hasn't already explained."""
    codes = rejected_partitions.get((partition_type, partition.namespace))
    status = partition.status
    reason = partition.reason
    if codes and status == "complete":
        status = "failed"
        reason = f"items rejected: {', '.join(sorted(codes))}"
    return {
        "type": partition_type,
        "parentPath": _partition_parent_path(cluster_name, partition),
        "status": status,
        **({"count": partition.count} if status == "complete" else {}),
        **({"reason": reason} if reason else {}),
    }


def _resolve_in_scope_namespaces(
    all_ns_items: list[dict], namespaces: list[str] | None, exclude_namespaces: list[str] | None
) -> list[str]:
    """The in-scope namespace set: an explicit list, or everything minus
    exclusions (default: exclude none). `all_ns_items` is whatever `_list_namespaces`
    managed to read -- empty if that listing itself failed and no explicit
    `namespaces` was given, which degrades to an empty scope rather than a
    guess."""
    if namespaces:
        return list(namespaces)
    excluded = set(exclude_namespaces or [])
    return [item["metadata"]["name"] for item in all_ns_items if item["metadata"]["name"] not in excluded]


def _list_namespaces(k8s: K8sClient) -> tuple[list[dict], Partition | None]:
    """Fetched exactly once per run (`run_discover` passes the result to
    both the scope resolver and the namespace-item pusher below) -- a
    failure here is reported as the "namespace" type's own partition;
    `None` on success (the caller fills in the real partition once it
    knows how many were actually in scope and pushed)."""
    try:
        body = k8s.get_raw("/api/v1/namespaces")
    except ForbiddenError:
        return [], Partition(namespace=None, status="forbidden")
    except ApiError as exc:
        return [], Partition(namespace=None, status="failed", reason=str(exc))
    items = body.get("items", [])
    for item in items:  # list items carry no TypeMeta -- see paginate.py
        item["kind"], item["apiVersion"] = "Namespace", "v1"
    return items, None


def _push_cluster_and_namespaces(
    k8s: K8sClient,
    cluster_name: str,
    cluster_uid: str,
    all_ns_items: list[dict],
    ns_list_failure: Partition | None,
    in_scope_namespaces: list[str],
    version_info: dict,
    sanitize_options: SanitizeOptions,
    pusher: BatchingPusher,
    counters: _Counters,
) -> None:
    # --- cluster item, first (platform-contract §5: push order cluster -> namespaces -> rest) ---
    # The k8sCluster rollup reads only the node count and node labels.
    nodes, nodes_unavailable = _list_best_effort(
        k8s, NODES_PATH, project=lambda n: {"metadata": {"labels": (n.get("metadata") or {}).get("labels") or {}}}
    )
    if nodes_unavailable is not None:
        counters.rollup_sources_unavailable[CLUSTER_SCOPE_KEY] = ["node"]
    api_groups = [g["name"] for g in k8s.get_raw(API_GROUPS_PATH).get("groups", [])]
    cluster_obj = {"apiVersion": "v1", "kind": "Cluster", "metadata": {"name": cluster_name, "uid": cluster_uid}}
    cluster_rollups = {"k8sCluster": k8s_cluster_rollup(version_info, None if nodes_unavailable else nodes, api_groups)}
    pusher.add(_build_item(cluster_name, cluster_chain(cluster_name), cluster_obj, sanitize_options, cluster_rollups))

    # --- namespaces ---
    if ns_list_failure is not None:
        if ns_list_failure.status == "forbidden":
            # Listing is forbidden, but an
            # explicit `namespaces` input still names namespaces we can GET
            # individually -- a minimal-privilege ServiceAccount is
            # commonly granted `get` on specific namespaces but not a
            # cluster-wide `list`. `in_scope_namespaces` is only non-empty
            # here when `namespaces` was explicit (the default,
            # everything-minus-exclusions scope has nothing to fall back
            # to without a list). Namespaced children still need a parent,
            # so a namespace that itself 403s/404s gets pushed as a STUB
            # item rather than dropped -- see `_get_namespace_or_stub`.
            for name in in_scope_namespaces:
                pusher.add(
                    _build_item(
                        cluster_name,
                        build_chain(cluster_name, NAMESPACE, name, None),
                        _get_namespace_or_stub(k8s, name),
                        sanitize_options,
                    ),
                    partition_key=("namespace", None),
                )
        # The aggregate partition stays exactly `ns_list_failure` (already
        # `forbidden`) either way: an explicit per-namespace GET can never
        # prove no OTHER namespace exists or was deleted, so it is never
        # safe to sweep on this information alone.
        counters.partitions.append(ns_list_failure)
        counters.partition_types.append("namespace")
        return

    in_scope = set(in_scope_namespaces)
    pushed = 0
    for ns_item in all_ns_items:
        name = (ns_item.get("metadata") or {}).get("name")
        if name in in_scope:
            pusher.add(
                _build_item(cluster_name, build_chain(cluster_name, NAMESPACE, name, None), ns_item, sanitize_options),
                partition_key=("namespace", None),
            )
            pushed += 1
    counters.partitions.append(Partition(namespace=None, status="complete", count=pushed))
    counters.partition_types.append("namespace")


_STUB_NAMESPACE_ANNOTATION = "k8s-discovery.runwhen.com/stub"


def _get_namespace_or_stub(k8s: K8sClient, name: str) -> dict:
    """One namespace, GET by name rather than listed -- see the forbidden-
    listing branch above. A namespace this ServiceAccount can't even GET
    (403/404) still gets pushed, as a stub: identity chain only, an empty
    document, and a marker annotation, so its children (which may well be
    readable even when the Namespace object itself isn't) have a parent to
    attach to."""
    try:
        obj = k8s.get_object(f"/api/v1/namespaces/{path_segment(name, 'namespace')}")
    except ForbiddenError:
        obj = None
    if obj is None:
        return {
            "kind": "Namespace",
            "apiVersion": "v1",
            "metadata": {"name": name, "annotations": {_STUB_NAMESPACE_ANNOTATION: "true"}},
        }
    obj["kind"], obj["apiVersion"] = "Namespace", "v1"
    return obj


def _fetch_namespace_rollup_sources(
    k8s: K8sClient, resources_by_type: dict[str, ApiResource], namespace: str
) -> NamespaceRollupContext:
    unavailable: set[str] = set()

    def _items(type_name: str) -> list[dict]:
        resource = resources_by_type.get(type_name)
        if resource is None:
            return []  # the type isn't served at all -- a structural fact, not a permissions gap
        path = api_resource_path(resource.group, resource.version, resource.plural, namespace=namespace)
        items, reason = _list_best_effort(k8s, path)
        if reason is not None:
            unavailable.add(type_name)
        return items

    # Built one namespace at a time; `build` keeps only compact rollup values,
    # so these raw lists are garbage the moment it returns.
    return NamespaceRollupContext.build(
        namespace=namespace,
        pods=_items("pod"),
        replicasets=_items("replicaset"),
        endpointslices=_items("endpointslice"),
        jobs=_items("job"),
        events=_items("event"),
        unavailable_sources=unavailable,
    )


def _push_everything_else(
    k8s: K8sClient,
    cluster_name: str,
    resources: list[ApiResource],
    in_scope_namespaces: list[str],
    sanitize_options: SanitizeOptions,
    pusher: BatchingPusher,
    counters: _Counters,
) -> None:
    # `resources` is the same discovery sweep `run_discover` already did to
    # build the pack payload -- discovering it twice would double the API
    # calls for no benefit and risk a different result the second time.
    # First wins: core/v1 is enumerated before every group, so "event" is
    # core/v1 Event (`involvedObject`, `message`) rather than
    # events.k8s.io/v1 Event (`regarding`, `note`), whose shape the rollups
    # don't read.
    resources_by_type: dict[str, ApiResource] = {}
    for r in resources:
        resources_by_type.setdefault(r.type_spec.type, r)
    rollup_ctx_by_namespace = {
        ns: _fetch_namespace_rollup_sources(k8s, resources_by_type, ns) for ns in in_scope_namespaces
    }
    for ns, ctx in rollup_ctx_by_namespace.items():
        if ctx.unavailable_sources:
            counters.rollup_sources_unavailable[ns] = sorted(ctx.unavailable_sources)

    for resource in resources:
        type_name = resource.type_spec.type
        if type_name in ("cluster", "namespace"):
            continue
        if resource.ephemeral or type_name in ROLLUP_SOURCE_TYPES:
            continue  # never pushed as items -- read only to feed rollups (handled above)

        for event in list_resource(k8s, resource, in_scope_namespaces):
            if isinstance(event, PageEvent):
                for raw_obj in event.page.items:
                    if type_name == "job" and is_job_owned_by_cronjob(raw_obj):
                        continue  # per-object ephemeral exception: a CronJob recreates its Job every run
                    namespace = event.page.namespace
                    chain = build_chain(
                        cluster_name,
                        resource.type_spec,
                        (raw_obj.get("metadata") or {}).get("name", ""),
                        namespace,
                    )
                    rollups = None
                    if namespace is not None:
                        uid = (raw_obj.get("metadata") or {}).get("uid", "")
                        name = (raw_obj.get("metadata") or {}).get("name", "")
                        rollups = rollup_ctx_by_namespace[namespace].rollups_for(type_name, uid, name)
                    pusher.add(
                        _build_item(cluster_name, chain, raw_obj, sanitize_options, rollups),
                        partition_key=(type_name, namespace),
                    )
            elif isinstance(event, PartitionEvent):
                counters.partitions.append(event.partition)
                counters.partition_types.append(type_name)
