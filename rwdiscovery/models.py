"""Pydantic models for the capability's typed outputs (platform-contract
§5). Schema is exported, not hand-written -- `scripts/export_schemas.py`
generates `capabilities/k8s-discovery/schemas/*.json` from these at build
time, the same convention `rw-checks-codecollection` uses for its own
`rw.findings.v1`."""

from __future__ import annotations

from typing import Any

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


class DiscoverySummary(BaseModel):
    """Output of the `discover` task -- `rw.discovery_summary.v1`. Bulk
    data never rides this envelope (it goes straight to papi through the
    sync API, platform-contract §3); this is only the run's own summary."""

    syncId: str
    packDigest: str
    counts: DiscoveryCounts
    partitions: DiscoveryPartitionCounts
    durationMs: int
    serverVersion: str
    clusterUid: str


class K8sObjectResult(BaseModel):
    """Output of the `inspect` task -- `rw.k8s_object.v1`. Exactly one of
    `object` (mode `get`) or `describe`+`events` (mode `describe`) is set
    when `found` is true; all three are null when `found` is false."""

    path: str
    found: bool
    object: dict[str, Any] | None = None
    describe: str | None = None
    events: list[dict[str, Any]] | None = Field(default=None)
