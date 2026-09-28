"""`K8sClient`'s own read-only guard (decision 7) -- a direct, fast unit
test alongside the fuller `RecordingApiClient`-based checks in
`test_discover_e2e.py`, which prove no real call path ever reaches this
with a non-GET method in the first place."""

from __future__ import annotations

import pytest

from rwdiscovery.k8s_client import K8sClient, ReadOnlyViolationError


def test_get_raw_only_ever_issues_get():
    calls: list[str] = []

    class _RecordingApi:
        def call_api(self, path, method, **kwargs):
            calls.append(method)
            raise AssertionError("unreachable: the fake's own return path isn't exercised by this test")

    with pytest.raises(AssertionError):
        K8sClient(api=_RecordingApi()).get_raw("/api/v1/namespaces")
    assert calls == ["GET"]


def test_a_non_get_method_is_refused_before_the_transport_is_ever_touched():
    """The guard itself: even if some future caller reached `_get` with a
    mutating verb, the transport would never see it."""

    class _Api:
        def call_api(self, *args, **kwargs):
            raise AssertionError("must never be called for a refused method")

    k8s = K8sClient(api=_Api())
    with pytest.raises(ReadOnlyViolationError, match="POST"):
        k8s._get("POST", "/api/v1/namespaces/acme-payments", None)
