"""Raw-JSON Kubernetes API access.

Deliberately bypasses the generated per-kind model classes
(`CoreV1Api.list_namespaced_pod()` and friends) by calling the API with
`_preload_content=False` and parsing the raw JSON ourselves. Every object
this module returns is a plain dict, straight off the wire, so
`sanitize.py` is the only thing that ever decides its shape -- never a
generated model's `to_dict()`, which drops unknown fields a CRD might
carry and re-cases everything to snake_case.

`auth_settings=["BearerToken"]` is passed on every call regardless of the
kubeconfig's actual auth mechanism: it is the only entry
`Configuration.auth_settings()` (the generated client) ever produces, and it
is a no-op when no bearer token is present -- exec-plugin and client-cert
auth both work through this unchanged, since cert auth happens at the TLS
layer, independent of `auth_settings`. Verified interactively against a
real GKE cluster (exec-plugin auth) during development.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

from kubernetes import client
from kubernetes.client.rest import ApiException


class ForbiddenError(RuntimeError):
    """A 403 -- distinct from a generic ApiError so callers can mark a
    partition `forbidden` rather than `failed` (platform-contract §3)."""

    def __init__(self, path: str):
        super().__init__(f"forbidden: {path}")
        self.path = path


class ApiError(RuntimeError):
    def __init__(self, path: str, status: int, reason: str, body: dict | None = None):
        super().__init__(f"{path}: {status} {reason}")
        self.path = path
        self.status = status
        self.reason = reason
        # The API server's `Status` object, when the error body parsed as
        # JSON -- a 410 on an expired `continue` token carries a fresh
        # (inconsistent) continuation token in `metadata.continue`.
        self.body = body or {}


def _status_body(exc: ApiException) -> dict:
    try:
        body = json.loads(exc.body) if exc.body else {}
    except (TypeError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


@dataclass
class K8sClient:
    api: client.ApiClient

    def get_raw(self, path: str, query_params: list[tuple[str, str]] | None = None) -> dict:
        try:
            response = self.api.call_api(
                path,
                "GET",
                query_params=query_params or [],
                header_params={"Accept": "application/json"},
                response_type=None,
                auth_settings=["BearerToken"],
                _preload_content=False,
                _return_http_data_only=True,
            )
        except ApiException as exc:
            if exc.status == 403:
                raise ForbiddenError(path) from exc
            raise ApiError(path, exc.status, exc.reason or "", _status_body(exc)) from exc
        return json.loads(response.data)

    def get_object(self, path: str) -> dict | None:
        """One object by its exact API path. `None` on 404 -- the
        `inspect` task's `found: false`."""
        try:
            return self.get_raw(path)
        except ApiError as exc:
            if exc.status == 404:
                return None
            raise

    def get_text(self, path: str, query_params: list[tuple[str, str]] | None = None) -> str:
        """Like `get_raw`, but for an endpoint that returns plain text, not
        JSON -- `pods/{pod}/log` is the only one this capability reads.
        Raises the same `ForbiddenError`/`ApiError` mapping as `get_raw`."""
        try:
            response = self.api.call_api(
                path,
                "GET",
                query_params=query_params or [],
                header_params={"Accept": "text/plain, */*"},
                response_type=None,
                auth_settings=["BearerToken"],
                _preload_content=False,
                _return_http_data_only=True,
            )
        except ApiException as exc:
            if exc.status == 403:
                raise ForbiddenError(path) from exc
            raise ApiError(path, exc.status, exc.reason or "", _status_body(exc)) from exc
        data = response.data
        return data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)


def path_segment(value: str, what: str) -> str:
    """An object or namespace name as one URL path segment. Kubernetes' own
    rule (apimachinery `IsValidPathSegmentName`): never empty, `.` or `..`,
    never containing `/` or `%` -- no real object can be named that way, so
    such a value can only be an attempt to address a different API path
    (`inspect`'s inputs come from an agent). Everything else is
    percent-encoded, so `?`, `#` or whitespace can't become a query string
    or fragment; the API server decodes it back."""
    if not value or value in (".", "..") or "/" in value or "%" in value:
        raise ValueError(f"invalid {what} for a Kubernetes API path: {value!r}")
    return quote(value, safe=":@")


def resource_path(
    group: str,
    version: str,
    plural: str,
    namespace: str | None = None,
    name: str | None = None,
) -> str:
    prefix = "/api/v1" if not group else f"/apis/{group}/{version}"
    segments = [prefix]
    if namespace is not None:
        segments += ["namespaces", path_segment(namespace, "namespace")]
    segments.append(plural)
    if name is not None:
        segments.append(path_segment(name, "name"))
    return "/".join(segments)
