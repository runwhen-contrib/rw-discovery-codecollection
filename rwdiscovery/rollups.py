"""Rollups -- aggregates of ephemeral objects, computed at the edge because
pods, ReplicaSets, EndpointSlices and Events are never stored as resources
in their own right. Every function here is pure: it takes
already-fetched, already-indexed collections and returns the facet value
`discover.py` attaches to a sync `Item.rollups[facetKey]`. Fetching and
indexing those collections (one `list_resource` call per ephemeral type,
per namespace) is `discover.py`'s job, not this module's -- keeping the
aggregation logic testable with plain synthetic fixtures, no fake API.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from .sanitize import mask_credential_shapes

# k8sEvents: Warning events in the last 60 minutes.
EVENTS_WINDOW_MINUTES = 60
# k8sCronJob: the last N job outcomes.
CRONJOB_LAST_N_JOBS = 5
_EVENT_MESSAGE_TRUNCATE = 300


def index_by_uid(items: list[dict]) -> dict[str, dict]:
    return {uid: item for item in items if (uid := (item.get("metadata") or {}).get("uid"))}


def resolve_workload_owner(pod: dict, replicasets_by_uid: dict[str, dict]) -> tuple[str, str] | None:
    """The pod's ultimate namespaced workload owner: (kind, uid). Walks the
    one indirection Kubernetes ever introduces, Pod -> ReplicaSet ->
    Deployment; every other controller (StatefulSet, DaemonSet, Job) owns
    its pods directly."""
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    if not owners:
        return None
    primary = next((o for o in owners if o.get("controller")), owners[0])
    if primary.get("kind") == "ReplicaSet":
        rs = replicasets_by_uid.get(primary.get("uid"))
        if rs:
            rs_owners = (rs.get("metadata") or {}).get("ownerReferences") or []
            rs_primary = next((o for o in rs_owners if o.get("controller")), None)
            if rs_primary:
                return (rs_primary.get("kind"), rs_primary.get("uid"))
        return ("ReplicaSet", primary.get("uid"))  # orphaned or unreadable RS
    return (primary.get("kind"), primary.get("uid"))


def group_pods_by_owner(pods: list[dict], replicasets_by_uid: dict[str, dict]) -> dict[tuple[str, str], list[dict]]:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for pod in pods:
        owner = resolve_workload_owner(pod, replicasets_by_uid)
        if owner is not None:
            grouped.setdefault(owner, []).append(pod)
    return grouped


# --- k8sPods -----------------------------------------------------------------


def k8s_pods_rollup(pods: list[dict]) -> dict:
    """`pods by phase, ready, restarts total/max, last termination reasons
    (OOMKilled...), nodes, imageIDs, oldest/newest`."""
    if not pods:
        return {
            "count": 0,
            "byPhase": {},
            "ready": 0,
            "restartsTotal": 0,
            "restartsMax": 0,
            "lastTerminationReasons": [],
            "nodes": [],
            "imageIds": [],
            "oldest": None,
            "newest": None,
        }

    by_phase: Counter[str] = Counter()
    ready = 0
    restarts_total = 0
    restarts_max = 0
    termination_reasons: set[str] = set()
    nodes: set[str] = set()
    image_ids: set[str] = set()
    timestamps: list[str] = []

    for pod in pods:
        status = pod.get("status") or {}
        by_phase[status.get("phase", "Unknown")] += 1
        for condition in status.get("conditions") or []:
            if condition.get("type") == "Ready" and condition.get("status") == "True":
                ready += 1
                break
        for cs in status.get("containerStatuses") or []:
            restarts = cs.get("restartCount", 0) or 0
            restarts_total += restarts
            restarts_max = max(restarts_max, restarts)
            last_state = cs.get("lastState") or {}
            terminated = last_state.get("terminated") or {}
            if terminated.get("reason"):
                termination_reasons.add(terminated["reason"])
            if cs.get("imageID"):
                image_ids.add(cs["imageID"])
        node_name = (pod.get("spec") or {}).get("nodeName")
        if node_name:
            nodes.add(node_name)
        created = (pod.get("metadata") or {}).get("creationTimestamp")
        if created:
            timestamps.append(created)

    return {
        "count": len(pods),
        "byPhase": dict(by_phase),
        "ready": ready,
        "restartsTotal": restarts_total,
        "restartsMax": restarts_max,
        "lastTerminationReasons": sorted(termination_reasons),
        "nodes": sorted(nodes),
        "imageIds": sorted(image_ids),
        "oldest": min(timestamps) if timestamps else None,
        "newest": max(timestamps) if timestamps else None,
    }


# --- k8sService endpoints ----------------------------------------------------


def k8s_service_endpoints_rollup(endpointslices: list[dict]) -> dict:
    """`ready/notReady endpoints` from the Service's EndpointSlices."""
    ready = 0
    not_ready = 0
    addresses: set[str] = set()
    for slice_obj in endpointslices:
        for endpoint in slice_obj.get("endpoints") or []:
            is_ready = (endpoint.get("conditions") or {}).get("ready", True)
            if is_ready:
                ready += 1
            else:
                not_ready += 1
            addresses.update(endpoint.get("addresses") or [])
    return {"ready": ready, "notReady": not_ready, "addressCount": len(addresses)}


# --- k8sEvents ---------------------------------------------------------------


def index_events_by_involved_uid(events: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for event in events:
        uid = (event.get("involvedObject") or {}).get("uid")
        if uid:
            grouped.setdefault(uid, []).append(event)
    return grouped


def _event_time(event: dict) -> str | None:
    return event.get("lastTimestamp") or event.get("eventTime") or event.get("firstTimestamp")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def k8s_events_rollup(
    events: list[dict],
    *,
    now: datetime | None = None,
    window_minutes: int = EVENTS_WINDOW_MINUTES,
) -> dict:
    """`Warning events in the last 60 min (reason, count, last seen, message
    truncated)`. `events` is already the full set attributed to one target
    (its own events plus, for a workload, its pods' events -- see
    `index_events_by_involved_uid`)."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(minutes=window_minutes)

    by_reason: dict[str, dict] = {}
    for event in events:
        if event.get("type") != "Warning":
            continue
        when = _parse_time(_event_time(event))
        if when is not None and when < cutoff:
            continue
        reason = event.get("reason", "Unknown")
        entry = by_reason.setdefault(
            reason,
            {"reason": reason, "count": 0, "lastSeen": None, "message": ""},
        )
        entry["count"] += event.get("count", 1) or 1
        when_str = _event_time(event)
        if when_str and (entry["lastSeen"] is None or when_str > entry["lastSeen"]):
            entry["lastSeen"] = when_str
            # Masked BEFORE truncating: a cut can split a credential (a PEM
            # without its END line, a DSN without its '@') so its pattern
            # no longer matches. Event messages are free text written by
            # controllers and often quote config, commands or DSNs.
            entry["message"] = mask_credential_shapes(event.get("message") or "")[:_EVENT_MESSAGE_TRUNCATE]

    warnings = sorted(by_reason.values(), key=lambda e: e["lastSeen"] or "", reverse=True)
    return {"windowMinutes": window_minutes, "warnings": warnings}


# --- k8sCronJob --------------------------------------------------------------


def k8s_cronjob_rollup(jobs: list[dict], *, last_n: int = CRONJOB_LAST_N_JOBS) -> dict:
    """`last N job outcomes` for a CronJob's owned Jobs."""

    def _start(job: dict) -> str:
        return (job.get("status") or {}).get("startTime") or (job.get("metadata") or {}).get("creationTimestamp", "")

    ordered = sorted(jobs, key=_start, reverse=True)[:last_n]
    outcomes = []
    for job in ordered:
        status = job.get("status") or {}
        if status.get("succeeded"):
            outcome = "succeeded"
        elif status.get("failed"):
            outcome = "failed"
        else:
            outcome = "running"
        outcomes.append(
            {
                "name": (job.get("metadata") or {}).get("name"),
                "outcome": outcome,
                "startTime": status.get("startTime"),
                "completionTime": status.get("completionTime"),
            }
        )
    return {"lastJobs": outcomes}


# --- k8sCluster --------------------------------------------------------------

_DISTRIBUTION_MARKERS = (
    ("-eks-", "eks"),
    ("-gke.", "gke"),
    ("-gke", "gke"),
    ("-aks", "aks"),
    ("+k3s", "k3s"),
    ("-rke2", "rke2"),
    ("openshift", "openshift"),
)


def _infer_distribution(git_version: str, nodes: list[dict]) -> str:
    lowered = (git_version or "").lower()
    for marker, name in _DISTRIBUTION_MARKERS:
        if marker in lowered:
            return name
    for node in nodes:
        labels = (node.get("metadata") or {}).get("labels") or {}
        if any(k.startswith("eks.amazonaws.com/") for k in labels):
            return "eks"
        if any(k.startswith("cloud.google.com/gke-") for k in labels):
            return "gke"
        if any(k.startswith("kubernetes.azure.com/") for k in labels):
            return "aks"
    return "unknown"


def k8s_cluster_rollup(version_info: dict, nodes: list[dict], api_groups: list[str]) -> dict:
    """`server version, distribution (EKS/GKE/AKS/OpenShift), node count,
    installed API groups`."""
    git_version = version_info.get("gitVersion", "")
    return {
        "serverVersion": git_version,
        "distribution": _infer_distribution(git_version, nodes),
        "nodeCount": len(nodes),
        "apiGroups": sorted(api_groups),
    }
