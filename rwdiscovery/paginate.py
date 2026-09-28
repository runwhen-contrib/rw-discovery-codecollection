"""Paginated, streaming listing of one API resource -- `limit=500` +
`continue` token, cluster-wide where RBAC allows it, otherwise per
in-scope namespace. Yields pages as they come
so `discover.py` can sanitize-and-push without ever holding the whole
cluster in memory.

Every listed item is stamped with its listing's `kind`/`apiVersion`: the
API server omits TypeMeta from list items for built-in types (a
`/api/v1/secrets` item has no `kind`), and `sanitize.py` dispatches on
`kind` -- without the stamp a listed Secret would take the generic path and
keep its `data`.

A 410 on an expired `continue` token (etcd compacted past the token's
resourceVersion -- five minutes by default, which a large type streamed
through papi pushes can outlast) is recovered, not failed: with the
inconsistent continuation token the 410 `Status` carries when the server
offers one (keys after the last one returned, at a newer resourceVersion --
an object present throughout the list is still always seen, so sweeping
stays safe), otherwise by restarting the list. A restart re-yields items
already yielded; re-pushing them is an idempotent upsert papi counts as
`unchanged`. The partition `count` itself does not over-count a restart --
`iter_pages`'s `on_restart` callback zeroes the caller's running total right
before the re-yielded items start arriving again.

Only a 403 triggers the per-namespace fallback -- "cluster-wide where RBAC
allows it, otherwise per namespace" is specifically about permission, not
about a slow/broken API server; any other error on the cluster-wide
attempt is reported as `failed` for every in-scope namespace rather than
silently retried scope-by-scope.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .enumerate import ApiResource
from .k8s_client import ApiError, ForbiddenError, K8sClient, resource_path

PAGE_LIMIT = 500
# Bounded so a server that keeps compacting under us fails the partition
# (safe: `failed` is never swept) instead of looping forever.
MAX_EXPIRED_CONTINUE_RECOVERIES = 3


@dataclass
class Page:
    namespace: str | None  # None for a cluster-scoped type's page
    items: list[dict]


@dataclass
class Partition:
    """One (type, namespace|cluster) partition's outcome -- feeds
    the sync commit's partitions directly (platform-contract §3)."""

    namespace: str | None
    status: str  # "complete" | "forbidden" | "failed"
    count: int = 0
    reason: str | None = None


@dataclass
class PageEvent:
    page: Page


@dataclass
class PartitionEvent:
    partition: Partition


Event = PageEvent | PartitionEvent


def type_meta_for(resource: ApiResource) -> tuple[str, str]:
    """`(kind, apiVersion)` for items listed under `resource`."""
    api_version = f"{resource.group}/{resource.version}" if resource.group else resource.version
    return resource.kind, api_version


def iter_pages(
    k8s: K8sClient,
    path: str,
    type_meta: tuple[str, str] | None = None,
    on_restart: Callable[[], None] | None = None,
) -> Iterator[list[dict]]:
    """Every page of `path`, following `continue` tokens. `type_meta`
    (`(kind, apiVersion)`) is stamped onto every item -- see the module
    docstring for why that is load-bearing for sanitization.

    `on_restart` is called once, right before the first page of a full
    restart-from-scratch listing (a 410 whose body carried no inconsistent
    continuation token) -- a caller counting items (`_list_cluster_scoped`
    and friends, below) uses it to zero its running total, so a restart's
    re-yielded items (see the module docstring) are counted once, not
    twice, in the partition's `count`."""
    continue_token: str | None = None
    recoveries = 0
    while True:
        query = [("limit", str(PAGE_LIMIT))]
        if continue_token:
            query.append(("continue", continue_token))
        try:
            body = k8s.get_raw(path, query_params=query)
        except ApiError as exc:
            if exc.status != 410 or not continue_token or recoveries >= MAX_EXPIRED_CONTINUE_RECOVERIES:
                raise
            recoveries += 1
            fresh_token = (exc.body.get("metadata") or {}).get("continue") or None
            if fresh_token is None and on_restart is not None:
                on_restart()
            continue_token = fresh_token
            continue
        items = body.get("items") or []
        if type_meta is not None:
            kind, api_version = type_meta
            for item in items:
                item["kind"] = kind
                item["apiVersion"] = api_version
        yield items
        continue_token = (body.get("metadata") or {}).get("continue")
        if not continue_token:
            return


def _list_cluster_scoped(k8s: K8sClient, resource: ApiResource) -> Iterator[Event]:
    path = resource_path(resource.group, resource.version, resource.plural)
    count = 0

    def _reset_count() -> None:
        nonlocal count
        count = 0

    try:
        for page in iter_pages(k8s, path, type_meta_for(resource), on_restart=_reset_count):
            count += len(page)
            yield PageEvent(Page(namespace=None, items=page))
    except ForbiddenError:
        yield PartitionEvent(Partition(namespace=None, status="forbidden"))
        return
    except ApiError as exc:
        yield PartitionEvent(Partition(namespace=None, status="failed", reason=str(exc)))
        return
    yield PartitionEvent(Partition(namespace=None, status="complete", count=count))


def _list_namespace(k8s: K8sClient, resource: ApiResource, namespace: str) -> Iterator[Event]:
    path = resource_path(resource.group, resource.version, resource.plural, namespace=namespace)
    count = 0

    def _reset_count() -> None:
        nonlocal count
        count = 0

    try:
        for page in iter_pages(k8s, path, type_meta_for(resource), on_restart=_reset_count):
            count += len(page)
            yield PageEvent(Page(namespace=namespace, items=page))
    except ForbiddenError:
        yield PartitionEvent(Partition(namespace=namespace, status="forbidden"))
        return
    except ApiError as exc:
        yield PartitionEvent(Partition(namespace=namespace, status="failed", reason=str(exc)))
        return
    yield PartitionEvent(Partition(namespace=namespace, status="complete", count=count))


def _list_cluster_wide_namespaced(
    k8s: K8sClient, resource: ApiResource, in_scope_namespaces: list[str]
) -> Iterator[Event]:
    path = resource_path(resource.group, resource.version, resource.plural)
    counts: dict[str, int] = dict.fromkeys(in_scope_namespaces, 0)
    in_scope = set(in_scope_namespaces)

    def _reset_counts() -> None:
        for ns in counts:
            counts[ns] = 0

    try:
        for page in iter_pages(k8s, path, type_meta_for(resource), on_restart=_reset_counts):
            by_ns: dict[str | None, list[dict]] = {}
            for item in page:
                ns = (item.get("metadata") or {}).get("namespace")
                if ns not in in_scope:
                    continue  # keep only objects in an in-scope namespace
                by_ns.setdefault(ns, []).append(item)
                counts[ns] = counts.get(ns, 0) + 1
            for ns, items in by_ns.items():
                yield PageEvent(Page(namespace=ns, items=items))
    except ForbiddenError:
        yield from _fallback_per_namespace(k8s, resource, in_scope_namespaces)
        return
    except ApiError as exc:
        for ns in in_scope_namespaces:
            yield PartitionEvent(Partition(namespace=ns, status="failed", reason=str(exc)))
        return
    for ns in in_scope_namespaces:
        yield PartitionEvent(Partition(namespace=ns, status="complete", count=counts.get(ns, 0)))


def _fallback_per_namespace(k8s: K8sClient, resource: ApiResource, in_scope_namespaces: list[str]) -> Iterator[Event]:
    for ns in in_scope_namespaces:
        yield from _list_namespace(k8s, resource, ns)


def list_resource(
    k8s: K8sClient,
    resource: ApiResource,
    in_scope_namespaces: list[str] | None = None,
) -> Iterator[Event]:
    if not resource.namespaced:
        yield from _list_cluster_scoped(k8s, resource)
        return
    yield from _list_cluster_wide_namespaced(k8s, resource, list(in_scope_namespaces or []))
