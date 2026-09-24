"""Sanitization at the source -- the first question a
security reviewer asks. Nothing leaves the cluster that a read-only platform
user shouldn't see. This module is the single place that decides what of a raw
Kubernetes object becomes the stored `document`/`status` (platform-contract §3's
Item shape) -- `discover` and `inspect` both call it, so no caller of either
task can pull a Secret's data through the side door.

Document shape this module produces (ours to define -- consumed only by our
own pack.yaml facet/rule JMESPath expressions, never re-served as a literal
Kubernetes object):

  - `metadata.managedFields` dropped; `kubectl.kubernetes.io/
    last-applied-configuration` dropped from annotations.
  - `status` split off and returned separately (never inside `document`),
    and walked by the same generic masking/truncation as everything else --
    a CRD's status is operator-written and can carry connection strings.
  - Secret: `data`/`stringData` removed; `secretKeys` (sorted key names)
    added at the top level. Annotation VALUES are replaced with a marker
    unless the key has one of a short allowlist of safe-by-convention
    prefixes (`kubernetes.io/`, `cert-manager.io/`, `meta.helm.sh/`,
    `app.kubernetes.io/`, `helm.sh/`) -- kapp/Argo "original manifest"
    annotations can carry the whole object, base64 `data` included, and a
    short base64 value embedded in a big blob is far below generic
    masking's high-entropy length floor. The rest is walked generically.
  - ConfigMap: `binaryData` removed; `binaryDataHashes` (key -> {size[,
    sha256]} of the DECODED bytes) added. `data` values are masked in place
    (never truncated -- Kubernetes already caps an object at 1 MiB) when
    `config_map_values="store"` (the default); with `config_map_values=
    "keysOnly"`, `data` itself is removed. Either way, `dataHashes` (key ->
    {size[, sha256]}) is added, so "this value changed" and "these
    ConfigMaps share a value" survive masking for values that weren't
    masked in the first place -- a value masked by its key name or a
    credential shape inside it gets `size` only, never a `sha256` of what
    it actually held, and `keysOnly` drops every hash's `sha256` outright
    (size only, for every value, masked or not). The rest (metadata,
    annotations) is walked generically.
  - Everywhere else: every `env[].value` (container env, keyed by its
    sibling `name`) and every other string leaf over 16 KB is masked/
    truncated by `mask_and_truncate_string`; so is the `value` of any other
    `{name, value}` pair (Argo CD helm parameters, Tekton params, ...),
    keyed by its `name`. `env[].valueFrom` is left
    untouched -- it is a reference, not a value, and references are what
    dependency rules (platform-contract §2) are built from.
"""

from __future__ import annotations

import copy
import hashlib
import math
import re
from base64 import b64decode
from dataclasses import dataclass, field
from typing import Any

MAX_STRING_BYTES = 16 * 1024  # any other string over this size is masked/truncated

# A narrow set of key/variable names -- deliberately
# excludes broad words like `key`, `auth`, `conn`, `dsn`, which name hosts
# and connection strings far more often than bare secrets. Real env/data
# keys are almost always compound (`DB_PASSWORD`, `API_TOKEN`,
# `CLIENT_SECRET`), so matching is done against the key with separators
# stripped, as a substring -- an exact-equality check would essentially
# never fire.
NARROW_SECRET_KEYS = frozenset(
    {"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "credentials"}
)
_NARROW_SECRET_KEYS_NORMALIZED = frozenset(k.replace("_", "") for k in NARROW_SECRET_KEYS)
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


# A key that NAMES an object rather than holding a value -- `secretName`
# (volumes, Ingress TLS, cert-manager Certificate), `tokenSecretRef`,
# `secretNamespace`. Its value is a reference, and references are edges
# (`k8s.ingress-uses-tls-secret`, `k8s.workload-uses-secret` in
# packs/kubernetes/pack.yaml read exactly these fields), so the substring
# match below must not whole-mask it.
_REFERENCE_KEY_SUFFIXES = ("name", "names", "ref", "refs", "namespace")


def _key_matches_narrow_secret_name(key: str) -> bool:
    normalized = _NON_ALNUM_RE.sub("", key.lower())
    if normalized.endswith(_REFERENCE_KEY_SUFFIXES):
        return False
    return any(keyword in normalized for keyword in _NARROW_SECRET_KEYS_NORMALIZED)


_LAST_APPLIED_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mask_marker(kind: str) -> str:
    return f"***MASKED:{kind}***"


def _truncate_marker(original: str) -> str:
    encoded = original.encode("utf-8", "surrogatepass")
    return f"***TRUNCATED:size={len(encoded)}:sha256={_sha256(encoded)}***"


# --- credential-shaped value detection ---------------------------------------

_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.DOTALL)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
# Cloud access-key formats -- prefixed token shapes with essentially no false
# positive rate. Not exhaustive; extend as new providers come up.
_CLOUD_KEY_RES = [
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[opsu]_[A-Za-z0-9]{36,}\b"),  # GitHub PAT/OAuth/app tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),  # GitHub fine-grained PAT
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack tokens
]
# `scheme://user:pass@host[:port][/path]` -- captures exactly the userinfo
# password so scheme, host, port and database survive.
_URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)([^:/?#\s@]+):([^@/?#\s]+)@")

# A "long high-entropy token" candidate: token-shaped (letters/digits plus
# the usual base64/base64url punctuation), at least 32 characters. Pure
# lowercase hex is excluded -- git SHAs and image digests match that shape
# constantly and are not secrets; masking them would hide exactly the kind
# of reference platform-contract §2's `dns_reference`/`reference` strategies
# want kept. Requiring a mix of case or base64 punctuation is what tells a real
# token apart from a hex digest.
_TOKEN_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/_=\-]{32,}\b")
# Lowercase letters, digits and '-' only: the DNS-1123 label alphabet every
# Kubernetes name is drawn from, which also covers UUIDs (`metadata.uid`,
# `ownerReferences[].uid` -- the `owner_reference` strategy's join key) and
# git shas / image digests. Generated names (`<release>-<chart>-<hash>-0`)
# and UUIDs easily clear the entropy threshold, so without this exemption
# the heuristic masks object names and UIDs -- the very references
# dependency rules join on.
_KUBE_NAME_RE = re.compile(r"^[0-9a-z-]+$")
_ENTROPY_THRESHOLD_BITS = 3.5


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_high_entropy_token(candidate: str) -> bool:
    if _KUBE_NAME_RE.match(candidate):
        return False  # k8s name / UUID / git sha / image digest -- see comments above
    has_upper = any(c.isupper() for c in candidate)
    has_lower = any(c.islower() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    has_punct = any(c in "+/_=-" for c in candidate)
    if not ((has_upper and has_lower) or (has_punct and (has_upper or has_lower) and has_digit)):
        return False
    return _shannon_entropy(candidate) >= _ENTROPY_THRESHOLD_BITS


def _mask_high_entropy_tokens(value: str) -> str:
    def _sub(m: re.Match) -> str:
        candidate = m.group(0)
        return _mask_marker("token") if _looks_like_high_entropy_token(candidate) else candidate

    return _TOKEN_CANDIDATE_RE.sub(_sub, value)


# --- `key=value`-shaped lines inside an otherwise-opaque string value ------
#
# A ConfigMap value (or a string-valued Argo CD/Helm parameter) is often
# itself a small config file -- a `.env`, `.properties`, or JSON-ish blob --
# baked in as one string. Its own credential-shaped-substring or high-entropy
# passes above only catch a password that itself LOOKS like a secret (a JWT,
# a long random token); a short, ordinary password (`hunter2`) never would.
# These three patterns catch `key=value`, `key: value`, `key = value` and
# `"key": "value"` lines and mask only the value half, when the key names a
# credential -- every other line, including a bare URL (whose scheme is
# followed by `://` with no space, so it never matches the colon form below)
# or a `key: value` reference line, is left untouched.
_UNQUOTED_EQUALS_KV_RE = re.compile(r"(?m)^(?P<prefix>[ \t]*(?P<key>[A-Za-z0-9_.\-]+)[ \t]*=[ \t]*)(?P<value>.+)$")
# A space is required after the colon so a URL's `scheme://` (no space after
# its colon) can never match this form.
_UNQUOTED_COLON_KV_RE = re.compile(r"(?m)^(?P<prefix>[ \t]*(?P<key>[A-Za-z0-9_.\-]+):[ \t]+)(?P<value>.+)$")
_QUOTED_KV_RE = re.compile(r'(?P<prefix>"(?P<key>[A-Za-z0-9_.\-]+)"\s*:\s*")(?P<value>(?:[^"\\]|\\.)*)(?P<suffix>")')


def _line_key_names_a_credential(key: str) -> bool:
    """The narrow key-name rule, restricted to the key's
    last dotted/underscored segment: a bare CONTAINS match (as used for
    JSON/env keys, `_key_matches_narrow_secret_name`) would whole-mask a
    line like `password_reset_url: https://...` -- a reference, not a
    secret -- because `password` is a substring of the normalized key.
    Normalizing away every separator and checking the *tail* instead
    catches `db.password`, `DB_PASSWORD` and `api_key` alike (their
    separator-stripped form ends with a narrow word) while leaving anything
    merely prefixed or infixed with one alone."""
    normalized = _NON_ALNUM_RE.sub("", key.lower())
    return any(normalized.endswith(keyword) for keyword in _NARROW_SECRET_KEYS_NORMALIZED)


def _mask_key_value_lines(value: str) -> str:
    def _sub_unquoted(m: re.Match) -> str:
        if not _line_key_names_a_credential(m.group("key")):
            return m.group(0)
        return f"{m.group('prefix')}{_mask_marker('credential')}"

    def _sub_quoted(m: re.Match) -> str:
        if not _line_key_names_a_credential(m.group("key")):
            return m.group(0)
        return f"{m.group('prefix')}{_mask_marker('credential')}{m.group('suffix')}"

    value = _UNQUOTED_EQUALS_KV_RE.sub(_sub_unquoted, value)
    value = _UNQUOTED_COLON_KV_RE.sub(_sub_unquoted, value)
    value = _QUOTED_KV_RE.sub(_sub_quoted, value)
    return value


def mask_credential_shapes(value: str) -> str:
    """Structure-preserving masking of any credential-shaped substring
    inside `value`. Order matters: the key=value line pass
    runs first (an explicit key name is the strongest signal there is), then
    PEM/JWT/cloud-key patterns, then the generic high-entropy pass, so a JWT
    (which is itself high-entropy) is reported as `jwt`, not `token`."""
    value = _mask_key_value_lines(value)
    value = _PEM_RE.sub(_mask_marker("pem"), value)
    value = _JWT_RE.sub(_mask_marker("jwt"), value)
    for pattern in _CLOUD_KEY_RES:
        value = pattern.sub(_mask_marker("cloud-key"), value)
    value = _URL_USERINFO_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}:****@", value)
    value = _mask_high_entropy_tokens(value)
    return value


def mask_and_truncate_string(value: str, key: str | None = None, *, truncate: bool = True) -> str:
    """The full per-string pipeline: whole-value masking by a narrow key
    name, then structure-preserving credential masking, then (unless
    `truncate=False`, used for ConfigMap `data` values) a size cap."""
    if key is not None and _key_matches_narrow_secret_name(key):
        return _mask_marker("credential")
    value = mask_credential_shapes(value)
    if truncate and len(value.encode("utf-8", "surrogatepass")) > MAX_STRING_BYTES:
        return _truncate_marker(value)
    return value


def _sanitize_env_list(env_list: list) -> list:
    """`env[].value` is masked using the sibling `name` as the credential
    key signal -- the dict key holding the literal is always `value`, never
    the variable's own name, so the generic key-based walk below can't see
    it. `env[].valueFrom` is left completely untouched: it is a reference,
    not a value, and references are kept because they're what dependency
    rules (platform-contract §2) turn into edges."""
    out = []
    for entry in env_list:
        if not isinstance(entry, dict):
            out.append(entry)
            continue
        entry = dict(entry)
        if isinstance(entry.get("value"), str):
            entry["value"] = mask_and_truncate_string(entry["value"], key=entry.get("name"))
        out.append(entry)
    return out


def _walk_generic(node: Any, key: str | None = None) -> Any:
    if isinstance(node, dict):
        # A `{name, value}` pair outside `env` (Argo CD helm parameters,
        # Tekton params, ...) is the same shape as an env entry: the
        # sibling `name` is the credential key signal for `value`.
        pair_name = node.get("name") if isinstance(node.get("value"), str) else None
        out = {}
        for k, v in node.items():
            if k == "env" and isinstance(v, list):
                out[k] = _sanitize_env_list(v)
            elif k == "value" and isinstance(pair_name, str):
                out[k] = mask_and_truncate_string(v, key=pair_name)
            else:
                out[k] = _walk_generic(v, key=k)
        return out
    if isinstance(node, list):
        return [_walk_generic(v, key=key) for v in node]
    if isinstance(node, str):
        return mask_and_truncate_string(node, key=key)
    return node


def _strip_common_metadata(metadata: dict) -> dict:
    metadata = dict(metadata)
    metadata.pop("managedFields", None)
    annotations = metadata.get("annotations")
    if isinstance(annotations, dict) and _LAST_APPLIED_ANNOTATION in annotations:
        annotations = dict(annotations)
        annotations.pop(_LAST_APPLIED_ANNOTATION, None)
        metadata["annotations"] = annotations
    return metadata


# Annotation VALUES a Secret keeps verbatim (subject to the usual generic
# masking below) -- everything else is replaced by a marker outright. kapp's
# `kapp.k14s.io/original`, Argo CD's equivalents, and similar "last full
# manifest" conventions serialize the WHOLE object as one annotation value,
# base64 `data` included -- generic masking's high-entropy floor is length-
# based and a short secret value (`aHVudGVyMg==`) sails straight through
# embedded in a big JSON blob. Keys always survive; only values this narrow.
_SECRET_ANNOTATION_VALUE_ALLOWED_PREFIXES = (
    "kubernetes.io/",
    "cert-manager.io/",
    "meta.helm.sh/",
    "app.kubernetes.io/",
    "helm.sh/",
)


def _sanitize_secret_annotations(annotations: dict) -> dict:
    out = {}
    for key, value in annotations.items():
        if key.startswith(_SECRET_ANNOTATION_VALUE_ALLOWED_PREFIXES):
            out[key] = value
        else:
            out[key] = _mask_marker("secret-annotation")
    return out


def _sanitize_secret(obj: dict) -> dict:
    data_keys = set(obj.get("data", {}) or {}).union(obj.get("stringData", {}) or {})
    metadata = obj.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("annotations"), dict):
        obj = {**obj, "metadata": {**metadata, "annotations": _sanitize_secret_annotations(metadata["annotations"])}}
    obj = _walk_generic({k: v for k, v in obj.items() if k not in ("data", "stringData")})
    # Added after the walk: the key names themselves must not be run through
    # the narrow-name rule (`secretKeys` contains "secret").
    obj["secretKeys"] = sorted(data_keys)
    return obj


def _sanitize_configmap(obj: dict, config_map_values: str) -> dict:
    data = obj.get("data") or {}
    binary_data = obj.get("binaryData") or {}
    obj = {
        **_walk_generic({k: v for k, v in obj.items() if k not in ("data", "binaryData")}),
        **{k: obj[k] for k in ("data", "binaryData") if k in obj},
    }
    keys_only = config_map_values == "keysOnly"

    # A value masked -- by its key name or by a credential shape inside it
    # (`mask_and_truncate_string` already decides both) -- gets no hash of
    # the original, only its size: a sha256 of a credential is still a
    # commitment to its exact value. `keysOnly` is stricter
    # still and drops every hash, masked or not -- the hosted/multi-tenant
    # mode this exists for wants no fingerprint of the value at all.
    masked_data: dict[str, str] = {}
    data_hashes = {}
    for key, value in data.items():
        raw = (value or "").encode("utf-8", "surrogatepass")
        masked_value = mask_and_truncate_string(value or "", key=key, truncate=False)
        masked_data[key] = masked_value
        entry = {"size": len(raw)}
        if not keys_only and masked_value == (value or ""):
            entry["sha256"] = _sha256(raw)
        data_hashes[key] = entry
    if data_hashes:
        obj["dataHashes"] = data_hashes

    if keys_only:
        obj.pop("data", None)
    elif data:
        # ConfigMap values are never truncated -- Kubernetes
        # already caps a whole object at 1 MiB -- masking still applies.
        obj["data"] = masked_data

    if binary_data:
        binary_hashes = {}
        for key, value in binary_data.items():
            try:
                decoded = b64decode(value)
            except Exception:  # noqa: BLE001 -- malformed base64 must not abort the whole sync
                decoded = (value or "").encode("utf-8", "surrogatepass")
            entry = {"size": len(decoded)}
            if not keys_only and not _key_matches_narrow_secret_name(key):
                entry["sha256"] = _sha256(decoded)
            binary_hashes[key] = entry
        obj["binaryDataHashes"] = binary_hashes
        obj.pop("binaryData", None)

    return obj


@dataclass
class SanitizeOptions:
    config_map_values: str = "store"  # "store" | "keysOnly"
    # Overlay JSONPath redactions. Deliberately minimal for now -- dotted
    # paths only, no wildcards -- see apply_extra_redactions' docstring.
    extra_redactions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.config_map_values not in ("store", "keysOnly"):
            raise ValueError(f"configMapValues must be 'store' or 'keysOnly', got {self.config_map_values!r}")


def apply_extra_redactions(document: dict, paths: list[str]) -> dict:
    """Minimal overlay redaction: a dotted path (`spec.foo.bar`, no
    wildcards) whose leaf is replaced with a masked marker if present. A
    fuller, workspace-configured overlay mechanism is expected to land
    later -- this is the hook it will grow from, not a JSONPath engine."""
    if not paths:
        return document
    document = copy.deepcopy(document)
    for path in paths:
        parts = path.split(".")
        node = document
        for part in parts[:-1]:
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if isinstance(node, dict) and parts[-1] in node and isinstance(node[parts[-1]], str):
            node[parts[-1]] = _mask_marker("overlay-redacted")
    return document


def sanitize(obj: dict, options: SanitizeOptions | None = None) -> tuple[dict, dict | None]:
    """Returns `(document, status)` -- platform-contract §3's Item shape.
    `obj` is a raw Kubernetes object as returned by the API (a plain dict,
    never parsed into the client's generated models -- see k8s_client.py)."""
    options = options or SanitizeOptions()
    obj = copy.deepcopy(obj)
    status = obj.pop("status", None)
    if "metadata" in obj:
        obj["metadata"] = _strip_common_metadata(obj["metadata"])

    kind = obj.get("kind", "")
    if kind == "Secret":
        document = _sanitize_secret(obj)
    elif kind == "ConfigMap":
        document = _sanitize_configmap(obj, options.config_map_values)
    else:
        document = _walk_generic(obj)

    document = apply_extra_redactions(document, options.extra_redactions)
    if status is not None:
        status = _walk_generic(status, key="status")
    return document, status
