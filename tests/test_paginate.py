from __future__ import annotations

from rwdiscovery.chain import resolve_type
from rwdiscovery.enumerate import ApiResource
from rwdiscovery.k8s_client import ApiError
from rwdiscovery.paginate import MAX_EXPIRED_CONTINUE_RECOVERIES, PageEvent, PartitionEvent, list_resource
from tests.fakes import FakeK8sClient


def _resource(group, version, kind, plural, namespaced):
    spec = resolve_type(group, version, kind, plural, namespaced)
    return ApiResource(
        group=group,
        version=version,
        kind=kind,
        plural=plural,
        namespaced=namespaced,
        verbs=("get", "list"),
        type_spec=spec,
        ephemeral=spec.ephemeral,
    )


def test_cluster_scoped_resource_pages_without_namespace():
    resource = _resource("", "v1", "Node", "nodes", namespaced=False)
    fake = FakeK8sClient(pages={"/api/v1/nodes": [{"items": [{"metadata": {"name": "acme-node-1"}}]}]})
    events = list(list_resource(fake, resource, in_scope_namespaces=[]))
    pages = [e for e in events if isinstance(e, PageEvent)]
    partitions = [e for e in events if isinstance(e, PartitionEvent)]
    assert len(pages) == 1
    assert pages[0].page.items[0]["metadata"]["name"] == "acme-node-1"
    assert partitions[0].partition.status == "complete"
    assert partitions[0].partition.count == 1


def test_cluster_wide_namespaced_listing_groups_by_namespace_and_filters_scope():
    resource = _resource("apps", "v1", "Deployment", "deployments", namespaced=True)
    fake = FakeK8sClient(
        pages={
            "/apis/apps/v1/deployments": [
                {
                    "items": [
                        {"metadata": {"name": "api", "namespace": "acme-payments"}},
                        {"metadata": {"name": "worker", "namespace": "acme-billing"}},
                        {"metadata": {"name": "sneaky", "namespace": "kube-system"}},
                    ]
                }
            ]
        }
    )
    events = list(list_resource(fake, resource, in_scope_namespaces=["acme-payments", "acme-billing"]))
    pages = [e.page for e in events if isinstance(e, PageEvent)]
    all_items = [item for p in pages for item in p.items]
    names = {item["metadata"]["name"] for item in all_items}
    assert names == {"api", "worker"}  # kube-system dropped -- out of scope

    partitions = {e.partition.namespace: e.partition for e in events if isinstance(e, PartitionEvent)}
    assert partitions["acme-payments"].status == "complete"
    assert partitions["acme-payments"].count == 1
    assert partitions["acme-billing"].count == 1


def test_forbidden_cluster_wide_falls_back_to_per_namespace():
    resource = _resource("apps", "v1", "Deployment", "deployments", namespaced=True)
    fake = FakeK8sClient(
        forbidden={"/apis/apps/v1/deployments"},
        pages={
            "/apis/apps/v1/namespaces/acme-payments/deployments": [
                {"items": [{"metadata": {"name": "api", "namespace": "acme-payments"}}]}
            ],
            "/apis/apps/v1/namespaces/acme-billing/deployments": [{"items": []}],
        },
    )
    events = list(list_resource(fake, resource, in_scope_namespaces=["acme-payments", "acme-billing"]))
    partitions = {e.partition.namespace: e.partition for e in events if isinstance(e, PartitionEvent)}
    assert partitions["acme-payments"].status == "complete"
    assert partitions["acme-payments"].count == 1
    assert partitions["acme-billing"].status == "complete"
    assert partitions["acme-billing"].count == 0


def test_per_namespace_forbidden_reports_that_namespace_forbidden_not_the_others():
    resource = _resource("apps", "v1", "Deployment", "deployments", namespaced=True)
    fake = FakeK8sClient(
        forbidden={
            "/apis/apps/v1/deployments",
            "/apis/apps/v1/namespaces/acme-restricted/deployments",
        },
        pages={"/apis/apps/v1/namespaces/acme-payments/deployments": [{"items": []}]},
    )
    events = list(list_resource(fake, resource, in_scope_namespaces=["acme-payments", "acme-restricted"]))
    partitions = {e.partition.namespace: e.partition for e in events if isinstance(e, PartitionEvent)}
    assert partitions["acme-payments"].status == "complete"
    assert partitions["acme-restricted"].status == "forbidden"


def test_generic_error_on_cluster_wide_listing_marks_every_namespace_failed():
    resource = _resource("apps", "v1", "Deployment", "deployments", namespaced=True)
    fake = FakeK8sClient(errors={"/apis/apps/v1/deployments": (500, "internal error")})
    events = list(list_resource(fake, resource, in_scope_namespaces=["acme-payments", "acme-billing"]))
    partitions = {e.partition.namespace: e.partition for e in events if isinstance(e, PartitionEvent)}
    assert partitions["acme-payments"].status == "failed"
    assert partitions["acme-billing"].status == "failed"


def test_pagination_follows_continue_token():
    resource = _resource("", "v1", "Node", "nodes", namespaced=False)
    fake = FakeK8sClient(
        pages={
            "/api/v1/nodes": [
                {"items": [{"metadata": {"name": "acme-node-1"}}]},
                {"items": [{"metadata": {"name": "acme-node-2"}}]},
            ]
        }
    )
    events = list(list_resource(fake, resource, in_scope_namespaces=[]))
    pages = [e.page for e in events if isinstance(e, PageEvent)]
    assert len(pages) == 2
    names = [p.items[0]["metadata"]["name"] for p in pages]
    assert names == ["acme-node-1", "acme-node-2"]


def test_list_items_are_stamped_with_the_listing_type_meta():
    """A real API server omits kind/apiVersion from list items of built-in
    types; sanitize.py dispatches on `kind`, so the stamp is what keeps a
    listed Secret out of the generic path."""
    secrets = _resource("", "v1", "Secret", "secrets", namespaced=True)
    fake = FakeK8sClient(
        pages={"/api/v1/secrets": [{"items": [{"metadata": {"name": "db", "namespace": "acme-payments"}}]}]}
    )
    items = [
        i for e in list_resource(fake, secrets, ["acme-payments"]) if isinstance(e, PageEvent) for i in e.page.items
    ]
    assert (items[0]["kind"], items[0]["apiVersion"]) == ("Secret", "v1")

    deployments = _resource("apps", "v1", "Deployment", "deployments", namespaced=True)
    fake = FakeK8sClient(
        pages={"/apis/apps/v1/deployments": [{"items": [{"metadata": {"name": "api", "namespace": "acme-payments"}}]}]}
    )
    items = [
        i for e in list_resource(fake, deployments, ["acme-payments"]) if isinstance(e, PageEvent) for i in e.page.items
    ]
    assert (items[0]["kind"], items[0]["apiVersion"]) == ("Deployment", "apps/v1")


class _ExpiringContinueFake:
    """Page 1 hands out a `stale` continue token that 410s. `fresh` is the
    inconsistent continuation token the 410 Status carries (None: the
    server offers none). `restart_items`: what a from-scratch re-list
    returns."""

    def __init__(self, fresh: str | None, restart_items: list[dict] | None = None, always_410: bool = False):
        self.fresh = fresh
        self.restart_items = restart_items or []
        self.always_410 = always_410
        self.continues: list[str | None] = []

    def get_raw(self, path, query_params=None):
        token = dict(query_params or []).get("continue")
        self.continues.append(token)
        if token is None:
            if self.continues.count(None) > 1:
                return {"items": self.restart_items}
            return {"items": [{"metadata": {"name": "acme-node-1"}}], "metadata": {"continue": "stale"}}
        if token == "stale" or self.always_410:
            raise ApiError(path, 410, "Gone", {"metadata": {"continue": self.fresh}} if self.fresh else {})
        return {"items": [{"metadata": {"name": "acme-node-2"}}]}


def _names_and_partition(events):
    names = [i["metadata"]["name"] for e in events if isinstance(e, PageEvent) for i in e.page.items]
    partition = next(e.partition for e in events if isinstance(e, PartitionEvent))
    return names, partition


def test_expired_continue_token_resumes_with_the_inconsistent_token_from_the_410():
    fake = _ExpiringContinueFake(fresh="fresh")
    names, partition = _names_and_partition(list(list_resource(fake, _resource("", "v1", "Node", "nodes", False))))
    assert names == ["acme-node-1", "acme-node-2"]
    assert fake.continues == [None, "stale", "fresh"]
    assert partition.status == "complete"


def test_expired_continue_token_without_a_fresh_one_restarts_the_list():
    fake = _ExpiringContinueFake(
        fresh=None, restart_items=[{"metadata": {"name": "acme-node-1"}}, {"metadata": {"name": "acme-node-2"}}]
    )
    names, partition = _names_and_partition(list(list_resource(fake, _resource("", "v1", "Node", "nodes", False))))
    assert names == ["acme-node-1", "acme-node-1", "acme-node-2"]  # re-yielded; re-pushing is an idempotent upsert
    assert fake.continues == [None, "stale", None]
    assert partition.status == "complete"
    # The restart re-yields "acme-node-1" (3 items total), but the count
    # must not double-count what was already seen before the restart --
    # only the restart's own from-scratch listing (2 items) is counted.
    assert partition.count == 2


def test_expired_continue_recovery_is_bounded_and_then_fails_the_partition():
    fake = _ExpiringContinueFake(fresh="fresh", always_410=True)
    _, partition = _names_and_partition(list(list_resource(fake, _resource("", "v1", "Node", "nodes", False))))
    assert partition.status == "failed"
    assert len(fake.continues) == 2 + MAX_EXPIRED_CONTINUE_RECOVERIES
