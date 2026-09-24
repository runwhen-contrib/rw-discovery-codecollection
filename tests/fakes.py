"""A fake Kubernetes API used by enumerate/paginate/discover tests -- an
in-process stand-in for `K8sClient`, never a real cluster or a mocked HTTP
layer, since the only surface those modules touch is `K8sClient.get_raw`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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
    # Plain-text routes (`get_text` -- pod log reads). Keyed the same way as
    # `single`/`forbidden`/`errors`, just a disjoint namespace of paths.
    text: dict[str, str] = field(default_factory=dict)

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

    def get_text(self, path: str, query_params: list[tuple[str, str]] | None = None) -> str:
        self.calls.append((path, query_params))
        if path in self.forbidden:
            raise ForbiddenError(path)
        if path in self.errors:
            status, reason = self.errors[path]
            raise ApiError(path, status, reason)
        if path in self.text:
            return self.text[path]
        raise ApiError(path, 404, "Not Found")
