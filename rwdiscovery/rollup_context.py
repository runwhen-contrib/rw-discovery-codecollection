"""Wires rollups.py's pure functions to one namespace's ephemeral
collections so `discover.py` can attach a `rollups`
value to each pushed item as it streams past, without re-fetching or
re-indexing per item.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from . import rollups as rl

# The rollup-relevant, always-ephemeral types this context needs per
# namespace, fetched once regardless of how many workloads/services are in
# scope there.
ROLLUP_SOURCE_TYPES = ("pod", "replicaset", "endpointslice", "event")

# Which pushed types get which rollup facet, and from what pods_by_owner key.
WORKLOAD_TYPES_WITH_POD_ROLLUP = ("deployment", "statefulset", "daemonset", "job")
_TYPE_TO_OWNER_KIND = {
    "deployment": "Deployment",
    "statefulset": "StatefulSet",
    "daemonset": "DaemonSet",
    "job": "Job",
}

# The single source of truth for "which rollup facet needs which of this
# namespace's source collections to have actually been read". If any one of
# a facet's listed sources came back unavailable (403/error, not a real
# empty list -- see `discover._list_best_effort`), `rollups_for` omits that
# facet entirely rather than emit a false empty/zero: the platform keeps
# whatever value it already has and ages it into `stale` by the facet's own
# TTL (`packs/kubernetes/pack.yaml`) instead. ReplicaSets map a Deployment's
# pods to it (Pod -> ReplicaSet -> Deployment is the one indirection
# Kubernetes introduces), so k8sPods needs both even though a
# StatefulSet/DaemonSet/Job owns its pods directly.
ROLLUP_FACET_REQUIRED_SOURCES: dict[str, tuple[str, ...]] = {
    "k8sPods": ("pod", "replicaset"),
    "k8sServiceEndpoints": ("endpointslice",),
    "k8sCronJobRuns": ("job",),
    # A workload's own events stay truthful even when its pods aren't
    # readable (see `_events_for`) -- only a forbidden/failed Event listing
    # itself makes k8sEvents untrustworthy.
    "k8sEvents": ("event",),
}


# The only fields `rollups.k8s_events_rollup`/`index_events_by_involved_uid`
# read. Only Warning events are ever rolled up.
_EVENT_FIELDS = ("type", "reason", "count", "message", "lastTimestamp", "eventTime", "firstTimestamp")


def _slim_warning_event(event: dict) -> dict:
    slim = {k: event.get(k) for k in _EVENT_FIELDS}
    slim["involvedObject"] = {"uid": (event.get("involvedObject") or {}).get("uid")}
    return slim


@dataclass
class NamespaceRollupContext:
    """Compact, precomputed rollup values for one namespace. `discover`
    builds one per in-scope namespace up front and keeps them all for the
    whole run (items of every type stream past across every namespace), so
    this must never retain the raw pods/ReplicaSets/EndpointSlices/Jobs/
    events it was built from -- that would hold every namespace's ephemeral
    objects at once, and this capability never holds the whole cluster in
    memory."""

    namespace: str
    # Which of this namespace's rollup source collections (`pod`,
    # `replicaset`, `endpointslice`, `job`, `event`) came back unavailable
    # this run -- see `ROLLUP_FACET_REQUIRED_SOURCES`.
    unavailable_sources: frozenset[str] = field(default_factory=frozenset)
    pods_rollup_by_owner: dict[tuple[str, str], dict] = field(default_factory=dict)
    pod_uids_by_owner: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    endpoints_rollup_by_service_name: dict[str, dict] = field(default_factory=dict)
    cronjob_rollup_by_uid: dict[str, dict] = field(default_factory=dict)
    warning_events_by_involved_uid: dict[str, list[dict]] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        namespace: str,
        pods: list[dict],
        replicasets: list[dict],
        endpointslices: list[dict],
        jobs: list[dict],
        events: list[dict],
        unavailable_sources: Iterable[str] = (),
    ) -> NamespaceRollupContext:
        replicasets_by_uid = rl.index_by_uid(replicasets)
        pods_by_owner = rl.group_pods_by_owner(pods, replicasets_by_uid)

        endpointslices_by_service_name: dict[str, list[dict]] = {}
        for slice_obj in endpointslices:
            service_name = (slice_obj.get("metadata") or {}).get("labels", {}).get("kubernetes.io/service-name")
            if service_name:
                endpointslices_by_service_name.setdefault(service_name, []).append(slice_obj)

        jobs_by_cronjob_uid: dict[str, list[dict]] = {}
        for job in jobs:
            for ref in (job.get("metadata") or {}).get("ownerReferences") or []:
                if ref.get("kind") == "CronJob":
                    jobs_by_cronjob_uid.setdefault(ref["uid"], []).append(job)

        warning_events = [_slim_warning_event(e) for e in events if e.get("type") == "Warning"]

        return cls(
            namespace=namespace,
            unavailable_sources=frozenset(unavailable_sources),
            pods_rollup_by_owner={owner: rl.k8s_pods_rollup(owned) for owner, owned in pods_by_owner.items()},
            pod_uids_by_owner={
                owner: [uid for pod in owned if (uid := (pod.get("metadata") or {}).get("uid"))]
                for owner, owned in pods_by_owner.items()
            },
            endpoints_rollup_by_service_name={
                name: rl.k8s_service_endpoints_rollup(slices) for name, slices in endpointslices_by_service_name.items()
            },
            cronjob_rollup_by_uid={uid: rl.k8s_cronjob_rollup(owned) for uid, owned in jobs_by_cronjob_uid.items()},
            warning_events_by_involved_uid=rl.index_events_by_involved_uid(warning_events),
        )

    def _events_for(self, uid: str, pod_uids: list[str]) -> list[dict]:
        events = list(self.warning_events_by_involved_uid.get(uid, []))
        for pod_uid in pod_uids:
            events.extend(self.warning_events_by_involved_uid.get(pod_uid, []))
        return events

    def _unavailable_for(self, facet_key: str) -> bool:
        return bool(self.unavailable_sources & set(ROLLUP_FACET_REQUIRED_SOURCES[facet_key]))

    def rollups_for(self, type_name: str, uid: str, name: str) -> dict:
        """Every rollup-populated facet this item's type declares in
        pack.yaml (`populator.kind: rollup`), keyed by facet key -- omitting
        a facet entirely whenever one of its required source collections
        (`ROLLUP_FACET_REQUIRED_SOURCES`) came back unavailable this run,
        rather than emitting it with a false empty/zero."""
        out: dict = {}
        pod_uids: list[str] = []
        if type_name in WORKLOAD_TYPES_WITH_POD_ROLLUP:
            owner = (_TYPE_TO_OWNER_KIND[type_name], uid)
            # Still gathered even when the facet itself is omitted below --
            # empty already when pods/replicasets are unavailable, so this
            # never widens what k8sEvents can see.
            pod_uids = self.pod_uids_by_owner.get(owner, [])
            if not self._unavailable_for("k8sPods"):
                out["k8sPods"] = self.pods_rollup_by_owner.get(owner) or rl.k8s_pods_rollup([])
        if type_name == "service" and not self._unavailable_for("k8sServiceEndpoints"):
            endpoints = self.endpoints_rollup_by_service_name.get(name)
            out["k8sServiceEndpoints"] = endpoints or rl.k8s_service_endpoints_rollup([])
        if type_name == "cronjob" and not self._unavailable_for("k8sCronJobRuns"):
            out["k8sCronJobRuns"] = self.cronjob_rollup_by_uid.get(uid) or rl.k8s_cronjob_rollup([])
        # k8sEvents applies to every type ("*" in pack.yaml) -- direct events
        # plus, for a rollup-bearing workload, its pods' events too. A
        # workload's own events stay truthful even when pod_uids came back
        # empty because pods/replicasets are unavailable (see above) --
        # only the Event listing itself being unavailable disqualifies it.
        if not self._unavailable_for("k8sEvents"):
            out["k8sEvents"] = rl.k8s_events_rollup(self._events_for(uid, pod_uids))
        return out
