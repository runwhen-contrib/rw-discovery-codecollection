"""Unit tests for `rwdiscovery.logsample` -- detection, multi-line join,
masking, grouping and the run-level sampler, against synthetic text (no
fake API for the pure functions) and `FakeK8sClient` for the sampler
itself. platform-contract log-patterns-v0 §1.1/§1.2.
"""

from __future__ import annotations

import itertools
import string
from datetime import UTC, datetime

from rwdiscovery.chain import ChainItem
from rwdiscovery.logsample import (
    LogEvent,
    PodSampleInfo,
    SamplingTarget,
    choose_pod,
    detect_error_start,
    group_key,
    join_events,
    mask,
    run_log_sample,
    sample_container,
    select_targets,
    strip_timestamp,
)
from tests.fakes import FakeK8sClient

# --- detection ----------------------------------------------------------


def test_detect_json_error_by_level_field():
    match = detect_error_start('{"level":"error","message":"connection refused"}')
    assert match is not None
    assert match.seed == "connection refused"


def test_detect_json_error_by_numeric_pino_level():
    match = detect_error_start('{"level":50,"msg":"disk full"}')
    assert match is not None
    assert match.seed == "disk full"


def test_json_info_level_is_not_an_error():
    assert detect_error_start('{"level":"info","msg":"all good"}') is None


def test_detect_logfmt_error():
    match = detect_error_start('time=2026-09-25T10:00:00Z level=error msg="db timeout"')
    assert match is not None


def test_logfmt_warn_is_not_detected():
    assert detect_error_start('level=warn msg="retrying"') is None


def test_detect_plain_text_level_token():
    match = detect_error_start("2026-09-25 10:00:00 ERROR database connection lost")
    assert match is not None


def test_plain_info_text_is_not_detected():
    assert detect_error_start("2026-09-25 10:00:00 INFO server started") is None


def test_detect_klog_error_line():
    match = detect_error_start("E0924 12:34:56.789012       1 controller.go:142] failed to sync: connection refused")
    assert match is not None


def test_klog_info_line_is_not_detected():
    assert detect_error_start("I0924 12:34:56.789012       1 controller.go:142] sync ok") is None


def test_detect_go_panic():
    assert detect_error_start("panic: runtime error: index out of range [3] with length 3") is not None


def test_detect_python_traceback_start():
    match = detect_error_start("Traceback (most recent call last):")
    assert match is not None
    assert match.is_python_traceback_start is True


# --- multi-line join ------------------------------------------------------


def _events_from(text: str) -> list[LogEvent]:
    lines = [strip_timestamp(line) for line in text.splitlines() if line]
    return join_events(lines)


def test_non_error_lines_are_ignored():
    text = "2026-09-25T10:00:00Z INFO server started\n2026-09-25T10:00:01Z INFO listening on :8080\n"
    assert _events_from(text) == []


def test_java_stack_trace_with_caused_by_is_one_event():
    text = (
        "2026-09-25T10:00:00.000000000Z ERROR Failed to process order\n"
        "2026-09-25T10:00:00.100000000Z\tat com.acme.OrderService.process(OrderService.java:42)\n"
        "2026-09-25T10:00:00.200000000Z\tat com.acme.OrderService.handle(OrderService.java:10)\n"
        "2026-09-25T10:00:00.300000000Z Caused by: java.lang.NullPointerException: order id is null\n"
        "2026-09-25T10:00:00.400000000Z\tat com.acme.OrderService.validate(OrderService.java:5)\n"
        "2026-09-25T10:00:00.500000000Z\t... 3 more\n"
    )
    events = _events_from(text)
    assert len(events) == 1
    assert len(events[0].raw_lines) == 6
    assert events[0].timestamp == "2026-09-25T10:00:00.000000000Z"


def test_python_traceback_is_one_event_ending_at_the_exception_line():
    text = (
        "2026-09-25T10:00:00.000000000Z Traceback (most recent call last):\n"
        '2026-09-25T10:00:00.100000000Z   File "app.py", line 10, in <module>\n'
        "2026-09-25T10:00:00.200000000Z     foo()\n"
        "2026-09-25T10:00:00.300000000Z ValueError: invalid literal for int() with base 10: 'x'\n"
        "2026-09-25T10:00:00.400000000Z INFO next request\n"
    )
    events = _events_from(text)
    assert len(events) == 1
    assert len(events[0].raw_lines) == 4
    assert events[0].raw_lines[-1].startswith("ValueError:")


def test_go_panic_is_one_event():
    text = (
        "2026-09-25T10:00:00.000000000Z panic: runtime error: index out of range [3] with length 3\n"
        "2026-09-25T10:00:00.100000000Z goroutine 1 [running]:\n"
        "2026-09-25T10:00:00.200000000Z main.foo(...)\n"
        "2026-09-25T10:00:00.300000000Z\t/app/main.go:42 +0x65\n"
    )
    events = _events_from(text)
    assert len(events) == 1
    assert events[0].raw_lines[0].startswith("panic:")


# --- masking --------------------------------------------------------------


def test_mask_matches_the_contract_example():
    assert mask('ERROR Timeout calling "idp" after 3000ms') == "ERROR Timeout calling <STR> after <NUM>ms"


def test_mask_gives_the_same_key_for_lines_differing_only_in_variable_parts():
    a = 'ERROR Timeout calling "idp" after 3000ms request_id=550e8400-e29b-41d4-a716-446655440000 from 10.0.0.5:5432'
    b = 'ERROR Timeout calling "auth" after 250ms request_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 from 10.1.2.3:6543'
    assert mask(a) == mask(b)
    assert group_key(mask(a)) == group_key(mask(b))


def test_mask_gives_a_different_key_for_a_different_message():
    a = mask("ERROR Timeout calling the identity provider")
    b = mask("ERROR Connection refused to database")
    assert a != b
    assert group_key(a) != group_key(b)


# --- grouping: examples and per-container caps -----------------------------


def _text_for_lines(lines: list[str]) -> str:
    return "\n".join(f"2026-09-25T10:00:00.000000000Z {line}" for line in lines) + "\n"


def test_examples_are_capped_by_count_and_bytes():
    lines = [f"ERROR Timeout calling {i}" for i in range(5)]
    # Every line masks to the SAME key ("<NUM>" swallows the differing digit).
    fake = FakeK8sClient(text={"/api/v1/namespaces/acme/pods/acme-api-1/log": _text_for_lines(lines)})
    groups, _bytes, status = sample_container(fake, namespace="acme", pod="acme-api-1", container="api", previous=False)
    assert status == "ok"
    assert len(groups) == 1
    assert groups[0]["count"] == 5
    assert len(groups[0]["examples"]) == 2  # MAX_EXAMPLES

    big_line = "ERROR " + ("x" * 10000)
    fake = FakeK8sClient(text={"/api/v1/namespaces/acme/pods/acme-api-2/log": _text_for_lines([big_line])})
    groups, _bytes, _status = sample_container(
        fake, namespace="acme", pod="acme-api-2", container="api", previous=False
    )
    assert len(groups[0]["examples"][0]["text"].encode()) <= 4096


def test_groups_per_container_are_capped():
    words = ["".join(p) for p in itertools.product(string.ascii_lowercase, repeat=2)][:51]
    lines = [f"ERROR failure-{w} occurred" for w in words]
    fake = FakeK8sClient(text={"/api/v1/namespaces/acme/pods/acme-api-1/log": _text_for_lines(lines)})
    groups, _bytes, status = sample_container(fake, namespace="acme", pod="acme-api-1", container="api", previous=False)
    assert status == "ok"
    assert len(groups) == 50  # MAX_GROUPS_PER_CONTAINER


# --- pod choice -------------------------------------------------------------


def test_choose_pod_prefers_the_most_restarted_unhealthy_pod():
    pods = [
        PodSampleInfo(name="pod-a", containers=("api",), restart_counts={"api": 0}, ready=True),
        PodSampleInfo(name="pod-b", containers=("api",), restart_counts={"api": 3}, ready=True),
        PodSampleInfo(name="pod-c", containers=("api",), restart_counts={"api": 0}, ready=False),
    ]
    chosen = choose_pod(pods, now=datetime(2026, 9, 25, tzinfo=UTC))
    assert chosen.name == "pod-b"


def test_choose_pod_rotates_among_healthy_pods_by_run_time():
    pods = [
        PodSampleInfo(name="pod-a", containers=("api",), restart_counts={"api": 0}, ready=True),
        PodSampleInfo(name="pod-b", containers=("api",), restart_counts={"api": 0}, ready=True),
    ]
    chosen_1 = choose_pod(pods, now=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC), window_seconds=900)
    chosen_2 = choose_pod(pods, now=datetime(2026, 1, 1, 0, 15, 0, tzinfo=UTC), window_seconds=900)
    assert {chosen_1.name, chosen_2.name} == {"pod-a", "pod-b"}
    assert chosen_1.name != chosen_2.name


def test_select_targets_orders_unhealthy_first():
    healthy = SamplingTarget(
        chain=[ChainItem("cluster", "c"), ChainItem("namespace", "ns"), ChainItem("deployment", "healthy")],
        namespace="ns",
        pods=[PodSampleInfo(name="p1", containers=("api",), restart_counts={"api": 0}, ready=True)],
    )
    unhealthy = SamplingTarget(
        chain=[ChainItem("cluster", "c"), ChainItem("namespace", "ns"), ChainItem("deployment", "unhealthy")],
        namespace="ns",
        pods=[PodSampleInfo(name="p2", containers=("api",), restart_counts={"api": 5}, ready=True)],
    )
    selected = select_targets([healthy, unhealthy], now=datetime(2026, 9, 25, tzinfo=UTC), max_workloads=150)
    assert selected[0] is unhealthy


# --- run-level orchestration -------------------------------------------------


def _target(name: str, namespace: str, pod: str, *, restarts: int = 0) -> SamplingTarget:
    return SamplingTarget(
        chain=[ChainItem("cluster", "acme-prod"), ChainItem("namespace", namespace), ChainItem("deployment", name)],
        namespace=namespace,
        pods=[PodSampleInfo(name=pod, containers=("api",), restart_counts={"api": restarts}, ready=True)],
    )


def test_forbidden_namespace_skips_its_other_pods():
    # svc-a is unhealthy (restarted) so `select_targets` always samples it
    # before the healthy svc-b, regardless of the run-time rotation --
    # deterministic which one hits the 403 first.
    target_a = _target("svc-a", "acme-payments", "svc-a-1", restarts=1)
    target_b = _target("svc-b", "acme-payments", "svc-b-1")
    fake = FakeK8sClient(
        forbidden={"/api/v1/namespaces/acme-payments/pods/svc-a-1/log"},
        text={"/api/v1/namespaces/acme-payments/pods/svc-b-1/log": _text_for_lines(["ERROR should never be read"])},
    )
    result = run_log_sample(fake, [target_a, target_b], now=datetime(2026, 9, 25, tzinfo=UTC))
    statuses = {w["chain"][-1]["name"]: w["status"] for w in result.workloads}
    assert statuses == {"svc-a": "forbidden", "svc-b": "forbidden"}
    assert result.summary["forbiddenNamespaces"] == ["acme-payments"]
    # svc-b's pod log was never actually requested.
    assert "/api/v1/namespaces/acme-payments/pods/svc-b-1/log" not in [p for p, _ in fake.calls]


def test_run_budget_stops_early_on_bytes_and_marks_truncated(monkeypatch):
    from rwdiscovery import logsample as logsample_module

    monkeypatch.setattr(logsample_module, "MAX_RUN_BYTES", 10)
    target_a = _target("svc-a", "ns-a", "svc-a-1")
    target_b = _target("svc-b", "ns-b", "svc-b-1")
    fake = FakeK8sClient(
        text={
            "/api/v1/namespaces/ns-a/pods/svc-a-1/log": _text_for_lines(["ERROR one"]),
            "/api/v1/namespaces/ns-b/pods/svc-b-1/log": _text_for_lines(["ERROR two"]),
        }
    )
    result = run_log_sample(fake, [target_a, target_b], now=datetime(2026, 9, 25, tzinfo=UTC), concurrency=1)
    statuses = {w["chain"][-1]["name"] for w in result.workloads if w["status"] == "truncated"}
    assert statuses  # at least one workload never got read because the budget was already spent
    assert result.summary["truncated"] is True


def test_run_budget_stops_early_on_time_and_marks_truncated(monkeypatch):
    from rwdiscovery import logsample as logsample_module

    monkeypatch.setattr(logsample_module.time, "monotonic", lambda: 10**9)
    target_a = _target("svc-a", "ns-a", "svc-a-1")
    fake = FakeK8sClient(text={"/api/v1/namespaces/ns-a/pods/svc-a-1/log": _text_for_lines(["ERROR one"])})
    result = run_log_sample(fake, [target_a], now=datetime(2026, 9, 25, tzinfo=UTC))
    assert result.workloads[0]["status"] == "truncated"
    assert result.summary["truncated"] is True
