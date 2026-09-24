"""The `inspect` task (platform-contract §5): `get` or `describe` one
object, no shell, sanitized output, path computed by the same chain
builder `discover` uses (this module's `path.py` mirror, never a call back
to papi -- see path.py's own docstring for why).
"""

from __future__ import annotations

import re
from pathlib import Path

from . import credentials
from .chain import CLUSTER, NAMESPACE, build_chain, parse_api_version
from .describe_render import render as render_describe
from .enumerate import ApiResource, discover_resources, resources_from_list
from .k8s_client import K8sClient
from .k8s_client import resource_path as api_resource_path
from .path import build_path
from .sanitize import SanitizeOptions, sanitize

EVENTS_LIMIT = 100
MODES = ("get", "describe")

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
    context: str | None = None,
    k8s_client: K8sClient | None = None,
) -> dict:
    """`k8s_client` is a test seam only, same convention as
    `discover.run_discover`. Every input arrives from an agent (the v13
    `kubectl` tool), so each is validated before it reaches an API path.

    `context` selects a named kubeconfig context to build that client from,
    instead of the kubeconfig's current-context -- ignored when `k8s_client`
    is supplied, since there is then no client left to build."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    k8s = k8s_client or K8sClient(credentials.build_api_client(kubeconfig_yaml, workdir, context=context))
    resource = _resolve_api_resource(k8s, kind, api_version)

    object_path = api_resource_path(resource.group, resource.version, resource.plural, namespace=namespace, name=name)
    raw_obj = k8s.get_object(object_path)

    chain = build_chain(cluster_name, resource.type_spec, name, namespace)
    specs_by_type = {resource.type_spec.type: resource.type_spec, CLUSTER.type: CLUSTER, NAMESPACE.type: NAMESPACE}
    path = build_path("kubernetes", chain, specs_by_type)

    if raw_obj is None:
        return {"path": path, "found": False}

    document, status = sanitize(raw_obj, SanitizeOptions())
    result: dict = {"path": path, "found": True}

    if mode == "get":
        result["object"] = {**document, **({"status": status} if status is not None else {})}
        return result

    uid = (raw_obj.get("metadata") or {}).get("uid", "")
    events = _events_for(k8s, namespace, uid)
    result["describe"] = render_describe(document, status, events, path)
    result["events"] = events
    return result
