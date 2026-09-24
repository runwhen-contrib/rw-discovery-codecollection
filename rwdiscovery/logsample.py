"""Error-log sampling -- a best-effort phase run once per `discover` run,
after the sync commit (platform-contract log-patterns-v0 §1.1/§1.2).

Lossy by design: a few pods per workload, a bounded window, a bounded
number of bytes -- whatever doesn't fit the budget is dropped, never
retried. Nothing here ever deletes anything papi already has; a scan that
sees less than last time just reports less.

Every function up to `sample_container` is pure -- detection, multi-line
join, masking and grouping take already-fetched text and return plain
data, so they're testable with string fixtures, no fake API. Only
`sample_container`/`run_log_sample` touch `K8sClient`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import rollups as rl
from .chain import ChainItem
from .k8s_client import ApiError, ForbiddenError, K8sClient, path_segment

logger = logging.getLogger(__name__)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("false", "0", "no", "")


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


# --- constants (env-overridable, platform-contract log-patterns-v0 §1.1) ----

ENABLED = _env_bool("RWDISCOVERY_LOGS_ENABLED", True)
SINCE_SECONDS = _env_int("RWDISCOVERY_LOGS_SINCE_SECONDS", 900)
MAX_WORKLOADS = _env_int("RWDISCOVERY_LOGS_MAX_WORKLOADS", 150)
PODS_PER_WORKLOAD = _env_int("RWDISCOVERY_LOGS_PODS_PER_WORKLOAD", 1)
MAX_BYTES_PER_CONTAINER = _env_int("RWDISCOVERY_LOGS_MAX_BYTES_PER_CONTAINER", 262144)
MAX_BYTES_PER_CONTAINER_PREVIOUS = _env_int("RWDISCOVERY_LOGS_MAX_BYTES_PER_CONTAINER_PREVIOUS", 65536)
MAX_RUN_BYTES = _env_int("RWDISCOVERY_LOGS_MAX_RUN_BYTES", 50 * 1024 * 1024)
MAX_RUN_SECONDS = _env_int("RWDISCOVERY_LOGS_MAX_RUN_SECONDS", 120)
CONCURRENCY = _env_int("RWDISCOVERY_LOGS_CONCURRENCY", 8)
MAX_EXAMPLES = _env_int("RWDISCOVERY_LOGS_MAX_EXAMPLES", 2)
MAX_EXAMPLE_BYTES = _env_int("RWDISCOVERY_LOGS_MAX_EXAMPLE_BYTES", 4096)
MAX_EXAMPLE_TRACE_BYTES = _env_int("RWDISCOVERY_LOGS_MAX_EXAMPLE_TRACE_BYTES", 8192)
MAX_GROUPS_PER_CONTAINER = _env_int("RWDISCOVERY_LOGS_MAX_GROUPS_PER_CONTAINER", 50)

MAX_EVENT_LINES = 60
MAX_EVENT_BYTES = 8192
MASKED_KEY_MAX_CHARS = 400


# --- pod inventory (gathered once per namespace by discover.py) -------------


@dataclass(frozen=True)
class PodSampleInfo:
    name: str
    containers: tuple[str, ...]
    restart_counts: dict[str, int] = field(default_factory=dict)
    ready: bool = False


@dataclass
class SamplingTarget:
    """One workload this run will consider sampling: its typed chain and
    the pods discover.py already listed for it. Bare pods (no owner) never
    become a target -- discover.py only builds one from a pushed workload
    item or a CronJob's owned Job."""

    chain: list[ChainItem]
    namespace: str
    pods: list[PodSampleInfo] = field(default_factory=list)


def pod_sample_info(pod: dict) -> PodSampleInfo:
    """The compact slice of a raw Pod object the sampler needs -- never the
    whole object (discover.py already fetched it for the rollups; this
    just re-reads the same fields)."""
    metadata = pod.get("metadata") or {}
    status = pod.get("status") or {}
    container_statuses = status.get("containerStatuses") or []
    containers = tuple(cs["name"] for cs in container_statuses if cs.get("name"))
    restart_counts = {cs["name"]: cs.get("restartCount", 0) or 0 for cs in container_statuses if cs.get("name")}
    ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions") or [])
    return PodSampleInfo(
        name=metadata.get("name", ""), containers=containers, restart_counts=restart_counts, ready=ready
    )


def pods_by_owner_for_sampling(pods: list[dict], replicasets: list[dict]) -> dict[tuple[str, str], list[PodSampleInfo]]:
    """`(kind, uid) -> [PodSampleInfo, ...]` for this namespace's pods,
    reusing `rollups.group_pods_by_owner` (Pod -> ReplicaSet -> Deployment;
    every other controller owns its pods directly) -- the same grouping
    discover.py's rollups already compute, just re-derived here into the
    compact shape this module needs, from the same raw lists (never
    retained past this call)."""
    replicasets_by_uid = rl.index_by_uid(replicasets)
    grouped = rl.group_pods_by_owner(pods, replicasets_by_uid)
    return {owner: [pod_sample_info(pod) for pod in owned] for owner, owned in grouped.items()}


# D8: patterns attach to the workload (deployment, statefulset, daemonset,
# cronjob, job) x container -- the only types discover.py accumulates a
# `SamplingTarget` for. A CronJob owns no pods of its own (see
# `pods_by_owner_for_sampling`'s docstring) -- its entry starts empty and is
# merged into by its owned Jobs' pods as they stream past.
SAMPLING_TYPES = ("deployment", "statefulset", "daemonset", "job", "cronjob")
# Which pushed type maps to which owner `kind` key in `pods_by_owner_for_sampling`'s
# result -- mirrors `rollup_context.py`'s own `_TYPE_TO_OWNER_KIND` (kept as
# a separate copy: that one is rollup-facet-specific and private).
WORKLOAD_OWNER_KIND = {"deployment": "Deployment", "statefulset": "StatefulSet", "daemonset": "DaemonSet", "job": "Job"}


# --- pod / workload selection (platform-contract §1.1 D5) -------------------


def _is_unhealthy(pod: PodSampleInfo) -> bool:
    return not pod.ready or any(count > 0 for count in pod.restart_counts.values())


def _rotation_index(now: datetime, length: int, window_seconds: int) -> int:
    bucket = int(now.timestamp() // max(window_seconds, 1))
    return bucket % length


def choose_pod(
    pods: list[PodSampleInfo], *, now: datetime, window_seconds: int = SINCE_SECONDS
) -> PodSampleInfo | None:
    """Up to 1 pod per workload: prefer unhealthy (restarts > 0 or not
    ready; the most-restarted first), otherwise rotate by run time so
    repeated runs tend to cover different replicas without any persisted
    cursor (D4)."""
    if not pods:
        return None
    unhealthy = sorted(
        (p for p in pods if _is_unhealthy(p)),
        key=lambda p: (-max(p.restart_counts.values(), default=0), p.name),
    )
    if unhealthy:
        return unhealthy[0]
    healthy = sorted(pods, key=lambda p: p.name)
    return healthy[_rotation_index(now, len(healthy), window_seconds)]


def _target_sort_key(target: SamplingTarget) -> str:
    return "/".join(f"{c.type}:{c.name}" for c in target.chain)


def select_targets(
    targets: list[SamplingTarget],
    *,
    now: datetime,
    max_workloads: int = MAX_WORKLOADS,
    window_seconds: int = SINCE_SECONDS,
) -> list[SamplingTarget]:
    """Which of this run's workloads (capped at `max_workloads`) actually
    get sampled: every workload with an unhealthy pod, then the rest
    rotated by run time (same rationale as `choose_pod`)."""
    unhealthy = sorted((t for t in targets if any(_is_unhealthy(p) for p in t.pods)), key=_target_sort_key)
    healthy = sorted((t for t in targets if not any(_is_unhealthy(p) for p in t.pods)), key=_target_sort_key)
    if len(unhealthy) >= max_workloads:
        return unhealthy[:max_workloads]
    remaining = max_workloads - len(unhealthy)
    if not healthy:
        rotated: list[SamplingTarget] = []
    else:
        start = _rotation_index(now, len(healthy), window_seconds)
        rotated = healthy[start:] + healthy[:start]
    return unhealthy + rotated[:remaining]


# --- error detection (platform-contract §1.1, generous by design) -----------


@dataclass(frozen=True)
class _StartMatch:
    # What `_masking_seed` should treat as "the first line" for this event
    # -- the raw (timestamp-stripped) text for every text-shaped detection,
    # but the extracted `message` (+ stack) for a JSON line, whose raw text
    # is a `{...}` blob that would mask into structural noise instead of a
    # meaningful key.
    seed: str
    is_python_traceback_start: bool = False


_JSON_LEVEL_KEYS = ("level", "severity", "levelname", "log.level", "@l", "lvl")
_JSON_ERROR_VALUES = {"error", "err", "fatal", "critical", "crit", "panic", "alert", "emerg"}
_JSON_MESSAGE_KEYS = ("message", "msg", "error", "err", "event", "log")
_JSON_STACK_KEYS = ("stack", "stack_trace", "exception")


def _json_level_value(obj: dict) -> object | None:
    for key in _JSON_LEVEL_KEYS:
        if key in obj:
            return obj[key]
    nested_log = obj.get("log")
    if isinstance(nested_log, dict) and "level" in nested_log:
        return nested_log["level"]
    return None


def _json_is_error_level(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in _JSON_ERROR_VALUES
    if isinstance(value, int | float) and not isinstance(value, bool):
        return value >= 50
    return False


def _json_message(obj: dict) -> str | None:
    for key in _JSON_MESSAGE_KEYS:
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _json_stack(obj: dict) -> str | None:
    for key in _JSON_STACK_KEYS:
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    nested_error = obj.get("error")
    if isinstance(nested_error, dict):
        stack = nested_error.get("stack")
        if isinstance(stack, str) and stack:
            return stack
    return None


def _try_json_error(text: str) -> str | None:
    if not (text.startswith("{") and text.endswith("}")):
        return None
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    level = _json_level_value(obj)
    if level is None or not _json_is_error_level(level):
        return None
    message = _json_message(obj) or text
    stack = _json_stack(obj)
    return f"{message}\n{stack}" if stack else message


_LOGFMT_LEVEL_RE = re.compile(r"(?:^|\s)level=(error|fatal|critical|panic)(?:\s|$)")
_KLOG_ERROR_RE = re.compile(r"^E\d{4}\s")
_LEVEL_TOKEN_RE = re.compile(r"(?<![A-Za-z])(ERROR|FATAL|CRITICAL|SEVERE|PANIC)(?![A-Za-z])")
_PY_TRACEBACK_START_TEXT = "Traceback (most recent call last):"
_PY_EXCEPTION_LINE_RE = re.compile(r"^\S*(Exception|Error)(:|$)")


def detect_error_start(text: str) -> _StartMatch | None:
    """`text` is one raw log line, kubelet timestamp already stripped.
    Generous: false positives are expected and removed downstream by the
    platform's LLM parse pass (D1/D7) -- under-detection is the mistake
    this must avoid, not over-detection."""
    stripped = text.strip()
    if not stripped:
        return None

    json_seed = _try_json_error(stripped)
    if json_seed is not None:
        return _StartMatch(seed=json_seed)

    if _LOGFMT_LEVEL_RE.search(text):
        return _StartMatch(seed=text)
    if _KLOG_ERROR_RE.match(text):
        return _StartMatch(seed=text)
    if "panic:" in text:
        return _StartMatch(seed=text)
    if _PY_TRACEBACK_START_TEXT in text:
        return _StartMatch(seed=text, is_python_traceback_start=True)
    if _PY_EXCEPTION_LINE_RE.match(text):
        return _StartMatch(seed=text)
    if "Exception in thread" in text:
        return _StartMatch(seed=text)
    if "Unhandled exception" in text:
        return _StartMatch(seed=text)
    if _LEVEL_TOKEN_RE.search(text):
        return _StartMatch(seed=text)
    return None


# --- kubelet `--timestamps` prefix + multi-line join -------------------------

_KUBELET_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s(.*)$")


def strip_timestamp(line: str) -> tuple[str, str | None]:
    """`(text, iso_timestamp)` -- `iso_timestamp` is `None` when the line
    doesn't carry the kubelet-prepended prefix (a truncated first line of a
    `limitBytes`-capped read, most often)."""
    match = _KUBELET_TIMESTAMP_RE.match(line)
    if not match:
        return line, None
    return match.group(2), match.group(1)


_CONTINUATION_PREFIXES = ("at ", "Caused by:", "... ", "---", 'File "', "goroutine ")


def _is_continuation(text: str) -> bool:
    if text[:1] in (" ", "\t"):
        return True
    return text.startswith(_CONTINUATION_PREFIXES)


@dataclass
class LogEvent:
    raw_lines: list[str]
    timestamp: str | None
    seed: str  # `detect_error_start`'s seed for this event's first line


def _event_bytes(lines: list[str]) -> int:
    return sum(len(line.encode("utf-8", "surrogatepass")) + 1 for line in lines)


def join_events(lines: Iterable[tuple[str, str | None]]) -> list[LogEvent]:
    """`lines`: `(text, timestamp)` pairs, already timestamp-stripped
    (`strip_timestamp`), in file order. Groups an error start line with its
    continuation lines (platform-contract §1.1) into one `LogEvent`;
    non-error lines between events are dropped (D1: errors only)."""
    events: list[LogEvent] = []
    current: LogEvent | None = None
    in_python_traceback = False

    def _close() -> None:
        nonlocal current, in_python_traceback
        if current is not None:
            events.append(current)
        current = None
        in_python_traceback = False

    for text, ts in lines:
        if current is not None:
            within_budget = (
                len(current.raw_lines) < MAX_EVENT_LINES and _event_bytes(current.raw_lines) < MAX_EVENT_BYTES
            )
            if in_python_traceback and within_budget:
                current.raw_lines.append(text)
                if _PY_EXCEPTION_LINE_RE.match(text):
                    _close()
                continue
            if within_budget and _is_continuation(text):
                current.raw_lines.append(text)
                continue
            _close()

        start = detect_error_start(text)
        if start is not None:
            current = LogEvent(raw_lines=[text], timestamp=ts, seed=start.seed)
            in_python_traceback = start.is_python_traceback_start

    _close()
    return events


# --- masking (grouping key only -- D2: examples stay raw) -------------------

_ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_EPOCH_TS_RE = re.compile(r"\b1\d{9}\b(?:\d{3})?|\b1\d{12}\b")
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,}\b")
_QUOTED_RE = re.compile(r'"[^"]*"|\'[^\']*\'')
_KV_RE = re.compile(r"(?<=[\s,{(])([A-Za-z_][\w.\-]*)=(\S+)")
_NUM_RE = re.compile(r"(?<![A-Za-z0-9_])\d+(?:\.\d+)?")
_WHITESPACE_RE = re.compile(r"\s+")


def mask(text: str) -> str:
    """Structure-preserving masking used only to build the grouping key
    (D2) -- never applied to the stored `examples[].text`."""
    text = _ISO_TS_RE.sub("<TS>", text)
    text = _EPOCH_TS_RE.sub("<TS>", text)
    text = _UUID_RE.sub("<UUID>", text)
    text = _IPV4_RE.sub("<IP>", text)
    text = _HEX_RE.sub("<HEX>", text)
    text = _QUOTED_RE.sub("<STR>", text)
    text = _KV_RE.sub(lambda m: f"{m.group(1)}=<*>", text)
    text = _NUM_RE.sub("<NUM>", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:MASKED_KEY_MAX_CHARS]


_TRACE_INDICATOR_RE = re.compile(r"Caused by:|Traceback \(most recent call last\)|goroutine ")
_EXCEPTION_CLASS_RE = re.compile(r"(?:Caused by:\s*)?([A-Za-z_][\w.$]*(?:Exception|Error))\b")


def _masking_seed(event: LogEvent) -> str:
    """message (first line only for traces, plus the exception class of
    the last `Caused by`/final line) -- platform-contract §1.1."""
    if len(event.raw_lines) == 1:
        return event.seed
    is_trace = bool(_TRACE_INDICATOR_RE.search(event.seed)) or any(
        _TRACE_INDICATOR_RE.search(line) for line in event.raw_lines[1:]
    )
    if not is_trace:
        return event.seed
    for line in reversed(event.raw_lines):
        match = _EXCEPTION_CLASS_RE.search(line)
        if match:
            exception_class = match.group(1)
            if exception_class in event.seed:
                return event.seed
            return f"{event.seed} {exception_class}"
    return event.seed


def group_key(masked: str) -> str:
    return hashlib.sha1(masked.encode("utf-8", "surrogatepass")).hexdigest()[:16]


# --- grouping -----------------------------------------------------------


def _cap_example_text(text: str, *, is_trace: bool) -> str:
    limit = MAX_EXAMPLE_TRACE_BYTES if is_trace else MAX_EXAMPLE_BYTES
    encoded = text.encode("utf-8", "surrogatepass")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", "ignore")


@dataclass
class _Group:
    container: str
    key: str
    masked: str
    count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    examples: list[dict] = field(default_factory=list)


def build_groups(
    events: list[LogEvent],
    *,
    container: str,
    pod: str,
    previous: bool,
    max_groups: int = MAX_GROUPS_PER_CONTAINER,
    max_examples: int = MAX_EXAMPLES,
) -> list[dict]:
    """One entry per masked key seen among `events` -- capped at
    `max_groups` (a group past the cap is dropped, never merged into an
    existing one: lossy by design, budgets win)."""
    groups: dict[str, _Group] = {}
    order: list[str] = []
    for event in events:
        masked = mask(_masking_seed(event))
        key = group_key(masked)
        group = groups.get(key)
        if group is None:
            if len(groups) >= max_groups:
                continue
            group = _Group(container=container, key=key, masked=masked)
            groups[key] = group
            order.append(key)
        group.count += 1
        ts = event.timestamp
        if ts:
            if group.first_seen is None or ts < group.first_seen:
                group.first_seen = ts
            if group.last_seen is None or ts > group.last_seen:
                group.last_seen = ts
        if len(group.examples) < max_examples:
            is_trace = len(event.raw_lines) > 1
            text = _cap_example_text("\n".join(event.raw_lines), is_trace=is_trace)
            group.examples.append({"text": text, "pod": pod, "at": ts, "previous": previous})
    return [
        {
            "container": g.container,
            "key": g.key,
            "masked": g.masked,
            "count": g.count,
            "firstSeen": g.first_seen,
            "lastSeen": g.last_seen,
            "examples": g.examples,
        }
        for g in (groups[k] for k in order)
    ]


# --- reading one container's log ---------------------------------------


def _log_path(namespace: str, pod: str) -> str:
    return f"/api/v1/namespaces/{path_segment(namespace, 'namespace')}/pods/{path_segment(pod, 'pod')}/log"


def sample_container(
    k8s: K8sClient, *, namespace: str, pod: str, container: str, previous: bool, since_seconds: int = SINCE_SECONDS
) -> tuple[list[dict], int, str]:
    """One container's log, read once: `(groups, bytes_read, status)`.
    `status` is `"ok"`, `"forbidden"` (403 -- the caller marks the whole
    namespace forbidden) or `"failed"` (any other error, e.g. the
    container never ran with `previous=true`)."""
    max_bytes = MAX_BYTES_PER_CONTAINER_PREVIOUS if previous else MAX_BYTES_PER_CONTAINER
    query = [
        ("container", container),
        ("sinceSeconds", str(since_seconds)),
        ("limitBytes", str(max_bytes)),
        ("timestamps", "true"),
    ]
    if previous:
        query.append(("previous", "true"))
    try:
        text = k8s.get_text(_log_path(namespace, pod), query)
    except ForbiddenError:
        return [], 0, "forbidden"
    except ApiError:
        return [], 0, "failed"
    bytes_read = len(text.encode("utf-8", "surrogatepass"))
    lines = [strip_timestamp(line) for line in text.splitlines() if line]
    events = join_events(lines)
    groups = build_groups(events, container=container, pod=pod, previous=previous)
    return groups, bytes_read, "ok"


# --- run-level orchestration ---------------------------------------------


@dataclass
class _RunBudget:
    lock: threading.Lock = field(default_factory=threading.Lock)
    started: float = field(default_factory=time.monotonic)
    bytes_used: int = 0
    truncated: bool = False

    def exhausted(self) -> bool:
        with self.lock:
            if self.truncated:
                return True
            if self.bytes_used >= MAX_RUN_BYTES or (time.monotonic() - self.started) >= MAX_RUN_SECONDS:
                self.truncated = True
                return True
            return False

    def add_bytes(self, n: int) -> None:
        with self.lock:
            self.bytes_used += n


def _sample_one_target(k8s: K8sClient, target: SamplingTarget, *, now: datetime, budget: _RunBudget) -> dict:
    chain_json = [{"type": c.type, "name": c.name} for c in target.chain]
    pod = choose_pod(target.pods, now=now)
    if pod is None:
        return {"chain": chain_json, "pod": None, "status": "ok", "bytesRead": 0, "groups": []}

    if budget.exhausted():
        return {"chain": chain_json, "pod": pod.name, "status": "truncated", "bytesRead": 0, "groups": []}

    groups: list[dict] = []
    bytes_read = 0
    status = "ok"
    for container in pod.containers:
        if budget.exhausted():
            status = "truncated"
            break
        previous = (pod.restart_counts.get(container, 0) or 0) > 0
        container_groups, container_bytes, container_status = sample_container(
            k8s, namespace=target.namespace, pod=pod.name, container=container, previous=previous
        )
        budget.add_bytes(container_bytes)
        bytes_read += container_bytes
        if container_status == "forbidden":
            return {"chain": chain_json, "pod": pod.name, "status": "forbidden", "bytesRead": bytes_read, "groups": []}
        if container_status == "failed" and status == "ok":
            status = "failed"
        groups.extend(container_groups)
    return {"chain": chain_json, "pod": pod.name, "status": status, "bytesRead": bytes_read, "groups": groups}


def _sample_namespace(
    k8s: K8sClient, namespace: str, targets: list[SamplingTarget], *, now: datetime, budget: _RunBudget
) -> tuple[list[dict], bool]:
    """Sequential within one namespace so a 403 can skip the rest of it
    without ever issuing their requests (platform-contract §1.1). Returns
    `(results, namespace_forbidden)`."""
    results: list[dict] = []
    forbidden = False
    for target in targets:
        if forbidden:
            chain_json = [{"type": c.type, "name": c.name} for c in target.chain]
            results.append({"chain": chain_json, "pod": None, "status": "forbidden", "bytesRead": 0, "groups": []})
            continue
        result = _sample_one_target(k8s, target, now=now, budget=budget)
        if result["status"] == "forbidden":
            forbidden = True
        results.append(result)
    return results, forbidden


@dataclass
class LogSampleResult:
    workloads: list[dict]
    summary: dict


def run_log_sample(
    k8s: K8sClient,
    targets: list[SamplingTarget],
    *,
    now: datetime | None = None,
    max_workloads: int = MAX_WORKLOADS,
    concurrency: int = CONCURRENCY,
) -> LogSampleResult:
    """Samples up to `max_workloads` of `targets` (already the light,
    per-namespace inventory discover.py accumulated), respecting the
    run-wide byte/time budget. Never raises for anything short of a bug in
    this module -- per-container/pod failures are folded into that
    workload's own `status` instead (D3: this phase must never fail the
    run)."""
    now = now or datetime.now(UTC)
    selected = select_targets(targets, now=now, max_workloads=max_workloads)
    budget = _RunBudget()

    by_namespace: dict[str, list[SamplingTarget]] = {}
    order: list[str] = []
    for target in selected:
        if target.namespace not in by_namespace:
            order.append(target.namespace)
        by_namespace.setdefault(target.namespace, []).append(target)

    workloads: list[dict] = []
    forbidden_namespaces: set[str] = set()
    if by_namespace:
        with ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(by_namespace)))) as pool:
            futures = {
                pool.submit(_sample_namespace, k8s, ns, by_namespace[ns], now=now, budget=budget): ns for ns in order
            }
            results_by_ns: dict[str, tuple[list[dict], bool]] = {}
            for future, ns in futures.items():
                results_by_ns[ns] = future.result()
        for ns in order:
            results, forbidden = results_by_ns[ns]
            workloads.extend(results)
            if forbidden:
                forbidden_namespaces.add(ns)

    total_groups = sum(len(w["groups"]) for w in workloads)
    total_bytes = sum(w["bytesRead"] for w in workloads)
    summary = {
        "workloads": len(workloads),
        "pods": sum(1 for w in workloads if w["pod"]),
        "bytes": total_bytes,
        "groups": total_groups,
        "forbiddenNamespaces": sorted(forbidden_namespaces),
        "seconds": round(time.monotonic() - budget.started, 3),
        "truncated": budget.truncated or len(targets) > len(selected),
    }
    return LogSampleResult(workloads=workloads, summary=summary)
