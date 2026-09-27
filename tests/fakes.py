"""A fake Kubernetes API used by enumerate/paginate/discover tests -- an
in-process stand-in for `K8sClient`, never a real cluster or a mocked HTTP
layer, since the only surface those modules touch is `K8sClient.get_raw`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace

from kubernetes.client.rest import ApiException

from rwdiscovery.k8s_client import ApiError, ForbiddenError


@dataclass
class FakeK8sClient:
    """Routes `get_raw(path, query_params)` to canned responses. `pages`
    maps an exact path (ignoring query params) to a list of page bodies,
    served in order as `continue` tokens are requested -- the fake's
    `continue` token is just the next page's index, as a string.
    `forbidden` and `errors` are sets/maps of paths that should raise
    instead."""

    pages: dict[str, list[dict]] = field(default_factory=dict)
    single: dict[str, dict] = field(default_factory=dict)
    forbidden: set[str] = field(default_factory=set)
    errors: dict[str, tuple[int, str]] = field(default_factory=dict)
    calls: list[tuple[str, list[tuple[str, str]] | None]] = field(default_factory=list)

    def get_raw(self, path: str, query_params: list[tuple[str, str]] | None = None) -> dict:
        self.calls.append((path, query_params))
        if path in self.forbidden:
            raise ForbiddenError(path)
        if path in self.errors:
            status, reason = self.errors[path]
            raise ApiError(path, status, reason)
        if path in self.pages:
            query = dict(query_params or [])
            index = int(query.get("continue", "0"))
            body = dict(self.pages[path][index])
            if index + 1 < len(self.pages[path]):
                body.setdefault("metadata", {})
                body["metadata"] = {**body.get("metadata", {}), "continue": str(index + 1)}
            return body
        if path in self.single:
            return self.single[path]
        raise ApiError(path, 404, "Not Found")

    def get_object(self, path: str) -> dict | None:
        try:
            return self.get_raw(path)
        except ApiError as exc:
            if exc.status == 404:
                return None
            raise


@dataclass
class RecordingApiClient:
    """A stand-in for `kubernetes.client.ApiClient`, at exactly the boundary
    `K8sClient.get_raw` calls (`call_api`) -- unlike `FakeK8sClient` above
    (which replaces `K8sClient` itself, the seam every other test in this
    suite uses), this sits one level lower, so a test can drive a full
    `run_discover`/`run_inspect` through the REAL `K8sClient.get_raw` and
    assert on the HTTP method it actually issued (decision 7: this
    capability must never issue anything but a GET, no matter what the
    credential itself could do). Wraps a `FakeK8sClient` for its canned
    responses, but speaks the real transport's shape: an `ApiException` on
    error, an object with `.data` (raw JSON bytes) on success."""

    fake: FakeK8sClient
    calls: list[tuple[str, str]] = field(default_factory=list)

    def call_api(self, path, method, query_params=None, **kwargs):
        self.calls.append((path, method))
        try:
            body = self.fake.get_raw(path, query_params)
        except ForbiddenError as exc:
            raise ApiException(status=403, reason="Forbidden") from exc
        except ApiError as exc:
            raise ApiException(status=exc.status, reason=exc.reason) from exc
        return SimpleNamespace(data=json.dumps(body).encode())
