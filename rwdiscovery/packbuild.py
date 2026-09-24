"""Builds the pack registration payload -- platform-contract §2's
`PUT /resource-packs/{name}` body.

Per platform-contract §2: the body has a STATIC part -- `name`,
`version`, `platform`, `types`, `facetDefinitions`, `dependencyRules` --
identical for every cluster this pack is registered against, and an
ADDITIVE part -- `additiveTypes`/`additiveFacetDefinitions` -- carrying
whatever THIS cluster actually discovered. The digest (and papi's
replace-on-change semantics) covers the static part only, so two clusters
with different CRDs installed never fight over who "owns" the pack's
digest; the additive entries are upserted independently and never removed
by another registration.

`types` (static) is never hand-maintained in `packs/kubernetes/pack.yaml`:
it is computed here from `chain.py`'s builtin table alone -- the one part
of the Kubernetes type table that really is identical everywhere.
`additiveTypes` carries whatever CustomResourceDefinitions this cluster
actually has, plus every OTHER listable API resource
discovery turns up that isn't either of those -- aggregated APIs
(`apiregistration.k8s.io/APIService`, metrics adapters, ...) and any other
resource this repo's builtin table doesn't yet enumerate. Without that
third source, `discover.py` could list and push items of a type whose
TypeSpec was never registered -- platform-contract §3 rejects an
unknown type outright. So there is exactly one place that knows the
Kubernetes type table (see pack.yaml's header comment). For each CRD,
`additionalPrinterColumns` becomes an entry in `additiveFacetDefinitions`'s
own `k8sSummary` facet's `expressionByType` map -- not a second
`k8sSummary` FacetDefinition, since a workspace may only register one row
per `(key, origin)` (platform-contract §2's `facet_definitions` unique
constraint); papi upserts the additive entry's `expressionByType` keys
into that one row rather than replacing it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

from .chain import BUILTIN_TYPES, CLUSTER, NAMESPACE, TypeSpec, is_ephemeral_type
from .enumerate import ApiResource
from .jsonpath_jmespath import jsonpath_to_jmespath

_REPO_PACK_YAML = Path(__file__).resolve().parent.parent / "packs" / "kubernetes" / "pack.yaml"
_IMAGE_PACK_YAML = Path("/app/packs/kubernetes/pack.yaml")


def _resolve_pack_yaml_path() -> Path:
    """Where the Kubernetes pack lives: RWDISCOVERY_PACK_PATH if set, else the
    source checkout (development, tests), else the image's copy.

    The installed package does not carry the pack: in the image `rwdiscovery`
    is pip-installed into a venv while `packs/` is copied to /app, so a path
    relative to this module alone would not exist there.
    """
    override = os.environ.get("RWDISCOVERY_PACK_PATH")
    if override:
        return Path(override)
    if _REPO_PACK_YAML.exists():
        return _REPO_PACK_YAML
    return _IMAGE_PACK_YAML


PACK_YAML_PATH = _resolve_pack_yaml_path()

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def load_pack_yaml(path: Path = PACK_YAML_PATH) -> dict:
    return yaml.safe_load(path.read_text())


def builtin_type_specs() -> list[TypeSpec]:
    """The two roots plus every hand-declared type in `chain.py`'s builtin
    table, deduplicated -- several (group, kind) keys can map to the same
    TypeSpec object (legacy API group aliases)."""
    seen: dict[str, TypeSpec] = {}
    for spec in (CLUSTER, NAMESPACE, *BUILTIN_TYPES.values()):
        seen[spec.type] = spec
    return list(seen.values())


def extra_discovered_type_specs(resources: list[ApiResource], crd_specs: list[TypeSpec]) -> list[TypeSpec]:
    """Every listable type `discover_resources()` turns up that isn't
    already a builtin or backed by a CustomResourceDefinition object --
    aggregated APIs and any other API resource this repo's builtin table
    doesn't yet enumerate. `resources` is already deduped by resolved type
    (`enumerate.py`'s `discover_resources`); CRD-backed kinds are excluded
    here since `crd_type_specs_and_summaries` already produced a richer
    TypeSpec for them (shortNames as `aliases`). Each remaining resource's
    own `type_spec` -- computed by `resolve_type` at enumeration time, the
    same `<kind>.<group>` fallback rule this module's CRD path uses -- is
    registered as-is."""
    covered = {s.type for s in builtin_type_specs()} | {s.type for s in crd_specs}
    seen: dict[str, TypeSpec] = {}
    for resource in resources:
        spec = resource.type_spec
        if spec.type in covered:
            continue
        seen[spec.type] = spec
    return list(seen.values())


def type_spec_to_dict(spec: TypeSpec) -> dict:
    return {
        "type": spec.type,
        "plural": spec.plural,
        "parent": spec.parent,
        "displayName": spec.display_name,
        "category": spec.category,
        "ephemeral": spec.ephemeral,
        "nameCase": spec.name_case,
        "aliases": list(spec.aliases),
        "native": dict(spec.native),
    }


def _facet_key_from_column_name(name: str) -> str:
    """A JMESPath multi-select-hash key: a bare identifier when the printer
    column name is already one (the common case: `Ready`, `Status`, `Age`),
    a quoted identifier otherwise."""
    if _IDENTIFIER_RE.fullmatch(name):
        return name
    return json.dumps(name)


def build_crd_summary_expression(printer_columns: list[dict]) -> str | None:
    """One JMESPath multi-select-hash expression combining every printer
    column into the `k8sSummary` facet's value for this CRD type."""
    parts = []
    for column in printer_columns:
        name = column.get("name")
        json_path = column.get("jsonPath")
        if not name or not json_path:
            continue
        key = _facet_key_from_column_name(name)
        parts.append(f"{key}: {jsonpath_to_jmespath(json_path)}")
    if not parts:
        return None
    return "{" + ", ".join(parts) + "}"


def _storage_version(versions: list[dict]) -> dict:
    return next((v for v in versions if v.get("storage")), versions[0] if versions else {})


def crd_type_specs_and_summaries(crd_objects: list[dict]) -> tuple[list[TypeSpec], dict[str, str]]:
    """One TypeSpec per CustomResourceDefinition object (as returned by the
    API -- see `sanitize.py`'s output, or a raw CRD dict in tests), and the
    `k8sSummary` `expressionByType` entries its printer columns produce."""
    specs: list[TypeSpec] = []
    summaries: dict[str, str] = {}
    for crd in crd_objects:
        spec = crd.get("spec") or {}
        group = spec.get("group", "")
        names = spec.get("names") or {}
        kind = names.get("kind", "")
        plural = names.get("plural", "")
        if not kind or not plural:
            continue
        namespaced = spec.get("scope", "Namespaced") == "Namespaced"
        versions = spec.get("versions") or []
        storage = _storage_version(versions)
        version_name = storage.get("name", "v1")
        type_name = f"{kind.lower()}.{group}" if group else kind.lower()
        plural_name = f"{plural}.{group}" if group else plural
        type_spec = TypeSpec(
            type=type_name,
            plural=plural_name,
            parent="namespace" if namespaced else "cluster",
            display_name=kind,
            category="custom",
            ephemeral=is_ephemeral_type(group, kind),
            name_case="preserve",
            aliases=tuple(names.get("shortNames") or ()),
            native={
                "apiGroup": group,
                "apiVersion": f"{group}/{version_name}" if group else version_name,
                "kind": kind,
            },
        )
        specs.append(type_spec)
        expression = build_crd_summary_expression(storage.get("additionalPrinterColumns") or [])
        if expression:
            summaries[type_name] = expression
    return specs, summaries


def _canonical_json(body: dict) -> str:
    """The server-computed digest (platform-contract §2) is a sha256 of
    canonical JSON. Computed here too so `discover.py` can log/compare
    locally -- papi's own computation over the same canonical form is
    authoritative for the actual no-op check."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def compute_digest(body: dict) -> str:
    return hashlib.sha256(_canonical_json(body).encode()).hexdigest()


def _additive_k8s_summary_facet(pack: dict, crd_summaries: dict[str, str]) -> dict | None:
    """The one additive FacetDefinition entry this capability ever sends:
    `k8sSummary`'s `expressionByType`, restricted to what THIS cluster's
    CRDs actually contributed. `title`/`description`/`appliesTo`/
    `volatility` are copied from the static definition (a FacetDefinition
    is validated as a whole -- platform-contract §2's grammar), but the
    generic `expression` fallback and the builtin `expressionByType`
    entries are left out: those already live in the static part, and
    duplicating them here would make the additive entry's shape depend on
    what the static part happens to contain today."""
    base = next((f for f in pack["facetDefinitions"] if f["key"] == "k8sSummary"), None)
    if base is None or not crd_summaries:
        return None
    return {
        "key": base["key"],
        "title": base["title"],
        "description": base["description"],
        "appliesTo": dict(base["appliesTo"]),
        "populator": {"kind": base["populator"]["kind"], "expressionByType": dict(crd_summaries)},
        "volatility": base["volatility"],
    }


def build_pack_payload(
    discovered_crds: list[dict] | None = None,
    discovered_resources: list[ApiResource] | None = None,
    pack_yaml: dict | None = None,
) -> dict[str, Any]:
    pack = pack_yaml if pack_yaml is not None else load_pack_yaml()

    static_types = [type_spec_to_dict(s) for s in builtin_type_specs()]
    crd_specs, crd_summaries = crd_type_specs_and_summaries(discovered_crds or [])
    additive_types = [type_spec_to_dict(s) for s in crd_specs]
    additive_types.extend(
        type_spec_to_dict(s) for s in extra_discovered_type_specs(discovered_resources or [], crd_specs)
    )

    facet_definitions = [dict(f) for f in pack["facetDefinitions"]]
    additive_facet = _additive_k8s_summary_facet(pack, crd_summaries)
    additive_facet_definitions = [additive_facet] if additive_facet else []

    # The static part: identical for every cluster this pack is registered
    # against -- the digest (platform-contract §2) is computed over this dict
    # alone, never the additive part below.
    body = {
        "name": pack["name"],
        "version": pack["version"],
        "platform": pack["platform"],
        "types": static_types,
        "facetDefinitions": facet_definitions,
        "dependencyRules": pack["dependencyRules"],
    }
    return {
        **body,
        "digest": compute_digest(body),
        "additiveTypes": additive_types,
        "additiveFacetDefinitions": additive_facet_definitions,
    }
