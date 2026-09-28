"""Pydantic models for the capability's typed outputs (platform-contract
§5). Schema is exported, not hand-written -- `scripts/export_schemas.py`
generates `capabilities/k8s-discovery/schemas/*.json` from these at build
time, the same convention `rw-checks-codecollection` uses for its own
`rw.findings.v1`."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, Field


class DiscoveryCounts(BaseModel):
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    deleted: int = 0
    held: int = 0


class DiscoveryPartitionCounts(BaseModel):
    complete: int = 0
    failed: int = 0
    forbidden: int = 0
    excluded: int = 0


class DiscoverySummary(BaseModel):
    """Output of the `discover` task -- `rw.discovery_summary.v1`. Bulk
    data never rides this envelope (it goes straight to papi through the
    sync API, platform-contract §3); this is only the run's own summary.

    `rollupSourcesUnavailable` maps a namespace name (or the cluster scope,
    key `""`) to the rollup source collections (`pod`, `replicaset`,
    `endpointslice`, `job`, `event`, `node`) that came back forbidden/failed
    this run -- any rollup facet needing one of them was omitted rather than
    reported with a false empty/zero. Capped so a cluster with many
    forbidden namespaces can't bloat this envelope."""

    # Bump when this model's shape changes in a way `export_schemas.py` must publish as a new
    # file (`schemas/discovery_summary.v<N>.json`) rather than overwrite -- see
    # docs/platform-contract.md's "versioned, immutable schemas" section. The old file stays;
    # `manifest.yaml`'s `schema:` ref moves to the new one.
    SCHEMA_VERSION: ClassVar[int] = 1

    syncId: str
    packDigest: str
    counts: DiscoveryCounts
    partitions: DiscoveryPartitionCounts
    durationMs: int
    serverVersion: str
    clusterUid: str
    rollupSourcesUnavailable: dict[str, list[str]] = Field(default_factory=dict)


# `inspect` was retired in favour of `cli` (platform-contract §7: one
# allow-listed `kubectl` command is now the agent's one read path), but this
# model and its published schema (schemas/k8s_object.v1.json) stay exactly
# as they were -- a published schema never changes or disappears
# (docs/platform-contract.md's "versioned, immutable schemas" section), and
# the model's own docstring below is baked into that schema's "description"
# (pydantic's json_schema()), so even a docstring edit here would drift the
# checked-in file out of sync with what export_schemas.py regenerates
# (tests/test_schemas.py enforces this). Do not edit the docstring; this
# comment is the only place left to note why an unreferenced model stays.
class K8sObjectResult(BaseModel):
    """Output of the `inspect` task -- `rw.k8s_object.v1`. Exactly one of
    `object` (mode `get`) or `describe`+`events` (mode `describe`) is set
    when `found` is true; all three are null when `found` is false."""

    # See DiscoverySummary.SCHEMA_VERSION above.
    SCHEMA_VERSION: ClassVar[int] = 1

    path: str
    found: bool
    object: dict[str, Any] | None = None
    describe: str | None = None
    events: list[dict[str, Any]] | None = Field(default=None)


class CliRejection(BaseModel):
    """Why the `cli` task's argv was refused (platform-contract §7) --
    never raised, always carried on `CliResult.rejected`."""

    reason: str
    hint: str


class CliResult(BaseModel):
    """Output of the `cli` task -- `rw.cli_result.v1`. `rejected` is set,
    and `exitCode` is -1, when `argv` failed validation before anything
    execs; every other field is the real `kubectl` subprocess result
    otherwise (`stdout`/`stderr` still present, empty, in the rejected
    case)."""

    # See DiscoverySummary.SCHEMA_VERSION above.
    SCHEMA_VERSION: ClassVar[int] = 1

    argv: list[str]
    exitCode: int
    stdout: str
    stderr: str
    truncated: bool
    stdoutBytes: int
    durationMs: int
    rejected: CliRejection | None = None
