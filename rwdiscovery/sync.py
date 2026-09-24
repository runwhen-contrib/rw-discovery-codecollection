"""Sync protocol client (platform-contract §3). `discover` is the only
caller; every request carries the lease-scoped `runwhen.resourceSync`
credential (platform-contract §4: `{"apiBaseUrl", "token", "workspace",
"expiresAt"}`), never a stored workspace credential.

Batching (`BatchingPusher`) uses its own, tighter
limit -- at most 200 items or 2 MB per push -- comfortably inside the
server's stated ceiling (platform-contract §3: <=500 items / <=5 MB). Idempotent
retries fall out for free: `(syncId, seq)` idempotency means a batch that
timed out mid-flight is simply re-sent with the same `seq` on the next
attempt (`SyncClient._request`'s retry loop), and papi returns "the stored
response unchanged" rather than double-applying it. Commit and abort are
idempotent the same way -- a replay is a 200 with the stored result, which
`_request`'s generic "any status < 300 is success" handling already treats
identically to a fresh one; there is nothing commit/abort-specific to
retry differently. `open_sync` needs its own handling instead: a 409 whose
stored sync was opened by THIS SAME capability run (a lost response, not a
lost request) is adopted rather than treated as someone else's conflict --
see its docstring.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

import requests

logger = logging.getLogger(__name__)

MAX_BATCH_ITEMS = 200
MAX_BATCH_BYTES = 2 * 1024 * 1024

_RETRYABLE_STATUSES = {500, 502, 503, 504}
MAX_RETRIES = 4
RETRY_BASE_DELAY_SECONDS = 1.0


class SyncClientError(RuntimeError):
    """`status`/`body` are set for an HTTP error response (never for a
    connection error); `body` is the parsed JSON body, or `{}`."""

    def __init__(self, message: str, status: int | None = None, body: dict | None = None):
        super().__init__(message)
        self.status = status
        self.body = body or {}


class SyncConflictError(SyncClientError):
    """A 409 opening a sync -- an unexpired open sync already exists for
    this `(source, scopePath)`. This client does not attempt to adopt or
    merge into someone else's open sync; the caller aborts this run and
    lets the next scheduled fire (or a fresh manual "run now") retry
    (platform-contract §3)."""

    def __init__(self, sync_id: str, lease_expires_at: str):
        super().__init__(f"sync already open: {sync_id!r} (lease expires {lease_expires_at})")
        self.sync_id = sync_id
        self.lease_expires_at = lease_expires_at


@dataclass(frozen=True)
class ResourceSyncCredential:
    api_base_url: str
    # Never in a repr: tracebacks, debuggers and log lines that format this
    # dataclass (or the SyncClient holding it) must not carry the token.
    token: str = field(repr=False)
    workspace: str

    @classmethod
    def parse(cls, raw: str) -> ResourceSyncCredential:
        data = json.loads(raw)
        return cls(
            api_base_url=data["apiBaseUrl"].rstrip("/"),
            token=data["token"],
            workspace=data["workspace"],
        )


def _json_body(response: requests.Response) -> dict:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


@dataclass
class SyncClient:
    credential: ResourceSyncCredential
    session: requests.Session = field(default_factory=requests.Session)
    timeout: float = 30.0

    def _url(self, path: str) -> str:
        return f"{self.credential.api_base_url}/api/v4/workspaces/{self.credential.workspace}{path}"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.credential.token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, body: dict) -> dict:
        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.request(
                    method,
                    self._url(path),
                    json=body,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
            except requests.exceptions.RequestException as exc:
                last_exc = exc
            else:
                if response.status_code < 300:
                    return response.json() if response.content else {}
                if response.status_code not in _RETRYABLE_STATUSES:
                    raise SyncClientError(
                        f"{method} {path}: {response.status_code} {response.text[:500]}",
                        status=response.status_code,
                        body=_json_body(response),
                    )
                last_exc = SyncClientError(f"{method} {path}: {response.status_code} {response.text[:500]}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BASE_DELAY_SECONDS * (2**attempt))
        raise SyncClientError(f"{method} {path} failed after {MAX_RETRIES + 1} attempts") from last_exc

    def put_pack(self, pack_payload: dict) -> dict:
        """Register the pack. The body carries no ``digest`` (platform-contract §2):
        papi computes the canonical digest itself and returns it.

        A response `skipped` entry (platform-contract §2: an
        additive type whose parent/plural conflicts with an existing
        registration) is logged, never raised -- the call still succeeds
        for every other type. Any item of a skipped type is simply
        rejected by papi when pushed, and `BatchingPusher` already fails
        that item's whole partition for exactly that reason."""
        body = {k: v for k, v in pack_payload.items() if k != "digest"}
        result = self._request("PUT", f"/resource-packs/{pack_payload['name']}", body)
        for entry in result.get("skipped") or []:
            logger.warning("pack registration skipped type %s: %s", entry.get("type"), entry.get("reason"))
        return result

    def open_sync(
        self,
        source: str,
        scope_path: str,
        capability_run_uuid: str | None = None,
        config_hash: str | None = None,
        pack: dict | None = None,
    ) -> dict:
        """Re-opening with the same `capabilityRunUuid` as an already-open
        sync for this scope (platform-contract §3) comes back
        either 200 (the untouched sync, if it never received a batch) or
        201 (a fresh sync, after papi aborts the partially-filled original
        -- no deletes). Both are plain success responses handled by the
        generic `_request` call below; this method just returns whatever
        `syncId` papi hands back, with no need to branch on the status
        code itself."""
        body: dict = {"source": source, "scopePath": scope_path, "mode": "full"}
        if capability_run_uuid:
            body["capabilityRunUuid"] = capability_run_uuid
        if config_hash:
            body["configHash"] = config_hash
        if pack:
            body["pack"] = pack
        try:
            return self._request("POST", "/resource-syncs", body)
        except SyncClientError as exc:
            # Only open's 409 means "a sync is already open" (platform-contract §3);
            # a 409 on the pack PUT (a type's parent/plural would change) or
            # on commit means something else and stays a plain error.
            if exc.status == 409:
                # Fallback only: a papi that answers a same-run re-open with
                # 200/201 (above) never reaches this branch for that case.
                # This still covers a 409 that is our own prior open call
                # whose success response never reached us (a lost response,
                # not a lost request -- the sync really did get created), or
                # an older papi that hasn't been updated to the 200/201
                # behaviour yet. If the already-open sync's stored
                # `capabilityRunUuid` is ours, adopt its syncId and carry on
                # -- `items`/`commit` are idempotent by (syncId, seq), so
                # resuming against it is safe. Anything else -- no
                # capabilityRunUuid on the open sync, or a different one --
                # stays a hard conflict: this client never adopts or merges
                # into someone else's open sync.
                if capability_run_uuid and exc.body.get("capabilityRunUuid") == capability_run_uuid:
                    return {
                        "syncId": exc.body.get("syncId", ""),
                        "leaseExpiresAt": exc.body.get("leaseExpiresAt", ""),
                    }
                raise SyncConflictError(exc.body.get("syncId", ""), exc.body.get("leaseExpiresAt", "")) from None
            raise

    def push_items(self, sync_id: str, seq: int, items: list[dict]) -> dict:
        return self._request("POST", f"/resource-syncs/{sync_id}/items", {"seq": seq, "items": items})

    def commit(self, sync_id: str, partitions: list[dict], stats: dict | None = None) -> dict:
        body: dict = {"partitions": partitions}
        if stats:
            body["stats"] = stats
        return self._request("POST", f"/resource-syncs/{sync_id}/commit", body)

    def abort(self, sync_id: str, reason: str) -> dict:
        return self._request("POST", f"/resource-syncs/{sync_id}/abort", {"reason": reason})


@dataclass
class BatchingPusher:
    """Accumulates sync items and flushes them in push-order (the caller is
    responsible for feeding items cluster -> namespaces -> rest, per
    platform-contract §5), tracking the running totals discover.py folds
    into its summary result.

    `rejected_partitions` (platform-contract §3: an unknown
    type or bad chain is `rejected`, never stored): every `items` response
    is checked for a `rejected` list, and each entry's `index` is resolved
    back to the `(type, namespace)` partition key the caller passed to
    `add()` for that item -- so `discover.py` can report that partition
    `failed` at commit rather than `complete`, and it is never swept. A
    `partition_key` of `None` (the cluster item; there is no reported
    partition for it) opts an item out of this tracking.

    `seq` starts at 1 (platform-contract §3), not 0. A fresh
    `BatchingPusher` is constructed for whichever `syncId` `open_sync`
    hands back -- the untouched sync from a same-run re-open, or a truly
    fresh one after papi aborts a partially-filled original -- so `seq`
    always restarts at 1 for that sync, never picking up wherever a prior,
    unrelated attempt left off."""

    client: SyncClient
    sync_id: str
    _seq: int = field(default=1, init=False)
    _batch: list[dict] = field(default_factory=list, init=False)
    _batch_bytes: int = field(default=0, init=False)
    _batch_partition_keys: list[tuple[str, str | None] | None] = field(default_factory=list, init=False)
    totals: dict[str, int] = field(
        default_factory=lambda: {"accepted": 0, "created": 0, "updated": 0, "unchanged": 0},
        init=False,
    )
    rejected: list[dict] = field(default_factory=list, init=False)
    rejected_partitions: dict[tuple[str, str | None], set[str]] = field(default_factory=dict, init=False)

    def add(self, item: dict, partition_key: tuple[str, str | None] | None = None) -> None:
        item_bytes = len(json.dumps(item).encode())
        if self._batch and (len(self._batch) >= MAX_BATCH_ITEMS or self._batch_bytes + item_bytes > MAX_BATCH_BYTES):
            self.flush()
        self._batch.append(item)
        self._batch_partition_keys.append(partition_key)
        self._batch_bytes += item_bytes

    def flush(self) -> None:
        if not self._batch:
            return
        response = self.client.push_items(self.sync_id, self._seq, self._batch)
        for key in self.totals:
            self.totals[key] += response.get(key, 0)
        rejected = response.get("rejected", [])
        self.rejected.extend(rejected)
        for entry in rejected:
            index = entry.get("index")
            if index is None or not (0 <= index < len(self._batch_partition_keys)):
                continue
            partition_key = self._batch_partition_keys[index]
            if partition_key is None:
                continue
            self.rejected_partitions.setdefault(partition_key, set()).add(entry.get("code", "unknown"))
        self._seq += 1
        self._batch = []
        self._batch_partition_keys = []
        self._batch_bytes = 0
