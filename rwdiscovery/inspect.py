"""The `inspect` task (platform-contract §5): `get`, `describe` or `logs`
one object, no shell, sanitized output, path computed by the same chain
builder `discover` uses (this module's `path.py` mirror, never a call back
to papi -- see path.py's own docstring for why).

`logs` (log-patterns-v0 platform-contract §1.3) is the agent's bounded
`kubectl logs` -- live confirmation of what the error-pattern catalog
already summarized. `kind` may be a workload (its pods are resolved via
`spec.selector.matchLabels`; a CronJob has none of its own, so its pods
come from its owned Jobs' selectors instead) or a bare `pod`.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import credentials
from .chain import CLUSTER, NAMESPACE, build_chain, parse_api_version
from .describe_render import render as render_describe
from .enumerate import ApiResource, discover_resources, resources_from_list
from .k8s_client import ApiError, ForbiddenError, K8sClient, path_segment
from .k8s_client import resource_path as api_resource_path
from .path import build_path
from .sanitize import SanitizeOptions, sanitize

EVENTS_LIMIT = 100
MODES = ("get", "describe", "logs")

# `logs` mode inputs (log-patterns-v0 platform-contract §1.3): caller-given
# values are clamped to these maxima -- never trusted outright, since every
# input arrives from an agent.
LOGS_DEFAULT_SINCE_SECONDS = 900
LOGS_MAX_SINCE_SECONDS = 86400
LOGS_DEFAULT_TAIL_LINES = 200
LOGS_MAX_TAIL_LINES = 2000
LOGS_DEFAULT_MAX_PODS = 3
LOGS_MAX_MAX_PODS = 10
# Hard output caps -- independent of the raw read, which is bounded on its
# own so a huge, ungrepped window can't be fetched wholesale from the API.
LOGS_MAX_TOTAL_BYTES = 64 * 1024
LOGS_MAX_LINE_CHARS = 2000
LOGS_FETCH_LIMIT_BYTES = 1024 * 1024

# `<group>/<version>` or a bare core `<version>`: group a DNS-1123
# subdomain, version a DNS-1035 label (every Kubernetes and CRD version
# name). `apiVersion` is interpolated into an API discovery path, so
# anything else is refused before it can address a different endpoint.
_API_VERSION_RE = re.compile(
    r"^(?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*/)?[a-z](?:[-a-z0-9]*[a-z0-9])?$"
)


class KindNotFoundError(LookupError):
    """Raised when `kind` (with the given `apiVersion`, if any) does not
    match any listable API resource this cluster advertises."""


def _resolve_api_resource(k8s: K8sClient, kind: str, api_version: str | None) -> ApiResource:
    if api_version:
        if not _API_VERSION_RE.match(api_version):
            raise ValueError(f"invalid apiVersion: {api_version!r}")
        group, version = parse_api_version(api_version)
        path = f"/api/{version}" if not group else f"/apis/{group}/{version}"
        body = k8s.get_raw(path)
        for resource in resources_from_list(group, version, body):
            if resource.kind == kind:
                return resource
        raise KindNotFoundError(f"kind {kind!r} not found in apiVersion {api_version!r}")

    for resource in discover_resources(k8s):
        if resource.kind == kind:
            return resource
    raise KindNotFoundError(f"kind {kind!r} not found via API discovery")


def _events_for(k8s: K8sClient, namespace: str | None, uid: str) -> list[dict]:
    """This object's events, sanitized like any other object read from the
    cluster (their messages are free text written by controllers). Filtered
    server-side: the first `EVENTS_LIMIT` events of a busy namespace rarely
    include the one object being described."""
    if not uid:
        return []
    path = "/api/v1/events" if namespace is None else api_resource_path("", "v1", "events", namespace=namespace)
    try:
        body = k8s.get_raw(
            path,
            query_params=[("fieldSelector", f"involvedObject.uid={uid}"), ("limit", str(EVENTS_LIMIT))],
        )
    except Exception:  # noqa: BLE001 -- events are a bonus for `describe`, never fatal to the inspect call
        return []
    events = [e for e in body.get("items", []) if (e.get("involvedObject") or {}).get("uid") == uid]
    return [sanitize(e)[0] for e in events]


def _clamp_int(value: int | None, *, default: int, maximum: int, minimum: int = 1) -> int:
    return max(minimum, min(value if value is not None else default, maximum))


def _pod_is_unhealthy(pod: dict) -> bool:
    status = pod.get("status") or {}
    ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions") or [])
    restarted = any((cs.get("restartCount", 0) or 0) > 0 for cs in status.get("containerStatuses") or [])
    return not ready or restarted


def _list_pods_by_labels(k8s: K8sClient, namespace: str, match_labels: dict) -> list[dict]:
    if not match_labels:
        return []
    selector = ",".join(f"{k}={v}" for k, v in sorted(match_labels.items()))
    path = api_resource_path("", "v1", "pods", namespace=namespace)
    try:
        body = k8s.get_raw(path, query_params=[("labelSelector", selector)])
    except Exception:  # noqa: BLE001 -- best effort; the caller just gets fewer/no pods
        return []
    return body.get("items", [])


def _resolve_logs_pods(k8s: K8sClient, resource: ApiResource, raw_obj: dict, namespace: str | None) -> list[dict]:
    """`kind` may be a bare Pod (itself the only candidate), a CronJob
    (which has no selector of its own -- its pods come from its owned
    Jobs' selectors), or any other workload (Deployment/StatefulSet/
    DaemonSet/ReplicaSet/Job all carry `spec.selector.matchLabels`
    directly)."""
    type_name = resource.type_spec.type
    if type_name == "pod":
        return [raw_obj]
    if namespace is None:
        return []
    if type_name == "cronjob":
        uid = (raw_obj.get("metadata") or {}).get("uid", "")
        try:
            jobs = k8s.get_raw(api_resource_path("batch", "v1", "jobs", namespace=namespace)).get("items", [])
        except Exception:  # noqa: BLE001 -- best effort; an unreadable Jobs listing just yields no pods
            jobs = []
        owned_jobs = [
            job
            for job in jobs
            if any(
                ref.get("kind") == "CronJob" and ref.get("uid") == uid
                for ref in (job.get("metadata") or {}).get("ownerReferences") or []
            )
        ]
        pods: list[dict] = []
        for job in owned_jobs:
            match_labels = ((job.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
            pods.extend(_list_pods_by_labels(k8s, namespace, match_labels))
        return pods
    match_labels = ((raw_obj.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
    return _list_pods_by_labels(k8s, namespace, match_labels)


def _select_logs_pods(pods: list[dict], max_pods: int) -> list[dict]:
    """Unhealthy first (stable within each group), capped at `max_pods`."""
    ordered = sorted(pods, key=lambda p: not _pod_is_unhealthy(p))
    return ordered[:max_pods]


def _compile_grep(pattern: str | None) -> tuple[re.Pattern | None, str | None]:
    """`(compiled, error)` -- an invalid regex is reported in the output,
    never raised (an agent-supplied pattern must not crash the call)."""
    if not pattern:
        return None, None
    try:
        return re.compile(pattern, re.IGNORECASE), None
    except re.error as exc:
        return None, f"invalid grep pattern: {exc}"


def _read_pod_container_log(
    k8s: K8sClient,
    *,
    namespace: str,
    pod: str,
    container: str | None,
    previous: bool,
    since_seconds: int,
    grep_re: re.Pattern | None,
) -> tuple[list[str], str | None]:
    """One (pod, container)'s log lines, grepped -- `(lines, error)`.
    `error` is `"forbidden"` or a short message; `lines` is `[]` either
    way. The raw read itself is capped at `LOGS_FETCH_LIMIT_BYTES`
    regardless of `grep`, which is applied locally, after the fetch."""
    query = [
        ("sinceSeconds", str(since_seconds)),
        ("limitBytes", str(LOGS_FETCH_LIMIT_BYTES)),
        ("timestamps", "false"),
    ]
    if container:
        query.append(("container", container))
    if previous:
        query.append(("previous", "true"))
    path = f"/api/v1/namespaces/{path_segment(namespace, 'namespace')}/pods/{path_segment(pod, 'pod')}/log"
    try:
        text = k8s.get_text(path, query)
    except ForbiddenError:
        return [], "forbidden"
    except ApiError as exc:
        return [], str(exc)[:200]
    lines = text.splitlines()
    if grep_re is not None:
        lines = [line for line in lines if grep_re.search(line)]
    return lines, None


def _run_logs_mode(
    k8s: K8sClient,
    *,
    resource: ApiResource,
    raw_obj: dict,
    namespace: str | None,
    container: str | None,
    previous: bool,
    since_seconds: int,
    tail_lines: int,
    grep: str | None,
    max_pods: int,
) -> dict:
    grep_re, grep_error = _compile_grep(grep)
    if grep_error:
        return {"mode": "logs", "pods": [], "totalLines": 0, "truncated": False, "error": grep_error}

    all_pods = _resolve_logs_pods(k8s, resource, raw_obj, namespace)
    selected = _select_logs_pods(all_pods, max_pods)

    pod_results: list[dict] = []
    total_lines = 0
    total_bytes = 0
    truncated = len(all_pods) > len(selected)

    for pod in selected:
        if total_bytes >= LOGS_MAX_TOTAL_BYTES:
            truncated = True
            break
        pod_name = (pod.get("metadata") or {}).get("name", "")
        containers = (
            [container]
            if container
            else [c.get("name") for c in (pod.get("spec") or {}).get("containers") or [] if c.get("name")]
        )
        for container_name in containers:
            lines, error = _read_pod_container_log(
                k8s,
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                previous=previous,
                since_seconds=since_seconds,
                grep_re=grep_re,
            )
            tail = lines[-tail_lines:] if tail_lines else []
            entry_truncated = len(tail) < len(lines)
            capped: list[str] = []
            for line in tail:
                if len(line) > LOGS_MAX_LINE_CHARS:
                    line = line[:LOGS_MAX_LINE_CHARS]
                    entry_truncated = True
                encoded_len = len(line.encode("utf-8", "surrogatepass")) + 1
                if total_bytes + encoded_len > LOGS_MAX_TOTAL_BYTES:
                    entry_truncated = True
                    truncated = True
                    break
                capped.append(line)
                total_bytes += encoded_len
            total_lines += len(capped)
            pod_results.append(
                {
                    "pod": pod_name,
                    "container": container_name,
                    "previous": previous,
                    "lines": capped,
                    "truncated": entry_truncated,
                    "error": error,
                }
            )
            if total_bytes >= LOGS_MAX_TOTAL_BYTES:
                break
        if total_bytes >= LOGS_MAX_TOTAL_BYTES:
            truncated = True
            break

    return {"mode": "logs", "pods": pod_results, "totalLines": total_lines, "truncated": truncated}


def run_inspect(
    *,
    kubeconfig_yaml: str,
    cluster_name: str,
    kind: str,
    name: str,
    namespace: str | None,
    api_version: str | None,
    mode: str,
    workdir: Path,
    container: str | None = None,
    previous: bool = False,
    since_seconds: int | None = None,
    tail_lines: int | None = None,
    grep: str | None = None,
    max_pods: int | None = None,
    k8s_client: K8sClient | None = None,
) -> dict:
    """`k8s_client` is a test seam only, same convention as
    `discover.run_discover`. Every input arrives from an agent (the v13
    `kubectl` tool), so each is validated before it reaches an API path.

    `container`/`previous`/`since_seconds`/`tail_lines`/`grep`/`max_pods`
    only matter for `mode="logs"` (log-patterns-v0 platform-contract
    §1.3); every other mode ignores them."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    k8s = k8s_client or K8sClient(credentials.build_api_client(kubeconfig_yaml, workdir))
    resource = _resolve_api_resource(k8s, kind, api_version)

    object_path = api_resource_path(resource.group, resource.version, resource.plural, namespace=namespace, name=name)
    raw_obj = k8s.get_object(object_path)

    chain = build_chain(cluster_name, resource.type_spec, name, namespace)
    specs_by_type = {resource.type_spec.type: resource.type_spec, CLUSTER.type: CLUSTER, NAMESPACE.type: NAMESPACE}
    path = build_path("kubernetes", chain, specs_by_type)

    if raw_obj is None:
        return {"path": path, "found": False}

    result: dict = {"path": path, "found": True}

    if mode == "logs":
        result["object"] = _run_logs_mode(
            k8s,
            resource=resource,
            raw_obj=raw_obj,
            namespace=namespace,
            container=container,
            previous=previous,
            since_seconds=_clamp_int(since_seconds, default=LOGS_DEFAULT_SINCE_SECONDS, maximum=LOGS_MAX_SINCE_SECONDS),
            tail_lines=_clamp_int(tail_lines, default=LOGS_DEFAULT_TAIL_LINES, maximum=LOGS_MAX_TAIL_LINES),
            grep=grep,
            max_pods=_clamp_int(max_pods, default=LOGS_DEFAULT_MAX_PODS, maximum=LOGS_MAX_MAX_PODS),
        )
        return result

    document, status = sanitize(raw_obj, SanitizeOptions())

    if mode == "get":
        result["object"] = {**document, **({"status": status} if status is not None else {})}
        return result

    uid = (raw_obj.get("metadata") or {}).get("uid", "")
    events = _events_for(k8s, namespace, uid)
    result["describe"] = render_describe(document, status, events, path)
    result["events"] = events
    return result
