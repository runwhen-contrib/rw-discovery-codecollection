from __future__ import annotations

import json
import logging

import pytest
import responses

from rwdiscovery.sync import (
    MAX_BATCH_BYTES,
    BatchingPusher,
    ResourceSyncCredential,
    SyncClient,
    SyncClientError,
    SyncConflictError,
)

CRED = ResourceSyncCredential(
    api_base_url="https://papi.acme.internal",
    token="jwt-token",
    workspace="acme-workspace",
)


def _client() -> SyncClient:
    return SyncClient(credential=CRED, timeout=1.0)


def test_resource_sync_credential_parses_json_and_strips_trailing_slash():
    raw = json.dumps(
        {
            "apiBaseUrl": "https://papi.acme.internal/",
            "token": "jwt-token",
            "workspace": "acme-workspace",
            "expiresAt": "2026-09-24T12:00:00Z",
        }
    )
    cred = ResourceSyncCredential.parse(raw)
    assert cred.api_base_url == "https://papi.acme.internal"
    assert cred.token == "jwt-token"


@responses.activate
def test_open_sync_posts_expected_body_and_auth_header():
    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs",
        json={"syncId": "sync-1", "leaseExpiresAt": "2026-09-24T12:45:00Z"},
        status=201,
    )
    result = _client().open_sync("k8s-discovery", "kubernetes/clusters/acme-prod-eu")
    assert result["syncId"] == "sync-1"
    request = responses.calls[0].request
    assert request.headers["Authorization"] == "Bearer jwt-token"
    body = json.loads(request.body)
    assert body == {"source": "k8s-discovery", "scopePath": "kubernetes/clusters/acme-prod-eu", "mode": "full"}


@responses.activate
def test_open_sync_conflict_raises_sync_conflict_error():
    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs",
        json={"syncId": "sync-existing", "leaseExpiresAt": "2026-09-24T12:45:00Z"},
        status=409,
    )
    try:
        _client().open_sync("k8s-discovery", "kubernetes/clusters/acme-prod-eu")
    except SyncConflictError as exc:
        assert exc.sync_id == "sync-existing"
    else:
        raise AssertionError("expected SyncConflictError")


@responses.activate
def test_open_sync_409_with_matching_capability_run_uuid_adopts_the_existing_sync():
    """A 409 on open is not always someone else's overlapping run -- it can
    be our own prior open call whose 201 response never reached us. If the
    already-open sync's stored `capabilityRunUuid` is ours, adopt its
    syncId rather than failing the whole run."""
    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs",
        json={"syncId": "sync-1", "leaseExpiresAt": "2026-09-24T12:45:00Z", "capabilityRunUuid": "run-uuid-1"},
        status=409,
    )
    result = _client().open_sync("k8s-discovery", "kubernetes/clusters/acme-prod-eu", capability_run_uuid="run-uuid-1")
    assert result["syncId"] == "sync-1"
    assert result["leaseExpiresAt"] == "2026-09-24T12:45:00Z"


@responses.activate
def test_open_sync_409_with_a_different_capability_run_uuid_still_conflicts():
    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs",
        json={"syncId": "sync-1", "leaseExpiresAt": "2026-09-24T12:45:00Z", "capabilityRunUuid": "someone-elses-run"},
        status=409,
    )
    try:
        _client().open_sync("k8s-discovery", "kubernetes/clusters/acme-prod-eu", capability_run_uuid="run-uuid-1")
    except SyncConflictError as exc:
        assert exc.sync_id == "sync-1"
    else:
        raise AssertionError("expected SyncConflictError")


@responses.activate
def test_open_sync_409_without_a_capability_run_uuid_on_either_side_still_conflicts():
    """No `capabilityRunUuid` passed by the caller, none echoed by papi --
    exactly today's behavior, unchanged (also covers a papi that hasn't
    been updated to echo the field on a 409 yet)."""
    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs",
        json={"syncId": "sync-existing", "leaseExpiresAt": "2026-09-24T12:45:00Z"},
        status=409,
    )
    try:
        _client().open_sync("k8s-discovery", "kubernetes/clusters/acme-prod-eu")
    except SyncConflictError as exc:
        assert exc.sync_id == "sync-existing"
    else:
        raise AssertionError("expected SyncConflictError")


@responses.activate
@pytest.mark.parametrize("status", [200, 201])
def test_open_sync_reopen_by_the_same_run_returns_whatever_sync_comes_back(status):
    """platform-contract §3: re-opening with the same
    `capabilityRunUuid` as an already-open sync for this scope comes back
    either 200 (untouched, no batches received yet) or 201 (a fresh sync,
    after papi aborts the partially-filled original). Neither needs
    special-casing -- both are plain success responses, and the caller
    just uses whichever `syncId` comes back."""
    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs",
        json={"syncId": "sync-2", "leaseExpiresAt": "2026-09-24T13:30:00Z"},
        status=status,
    )
    result = _client().open_sync("k8s-discovery", "kubernetes/clusters/acme-prod-eu", capability_run_uuid="run-uuid-1")
    assert result["syncId"] == "sync-2"
    assert result["leaseExpiresAt"] == "2026-09-24T13:30:00Z"


@responses.activate
def test_commit_retries_on_5xx_then_succeeds_with_the_stored_result(monkeypatch):
    """Commit replays are idempotent on the server (a 200 with the stored
    result) -- `_request`'s generic <300-is-success handling already covers
    this for commit exactly as it does for push_items; exercised here so
    that stays true."""
    from rwdiscovery import sync as sync_module

    monkeypatch.setattr(sync_module.time, "sleep", lambda _seconds: None)
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/commit"
    responses.add(responses.POST, url, status=503)
    responses.add(
        responses.POST,
        url,
        json={"status": "committed", "counts": {"created": 1, "updated": 0, "unchanged": 0, "deleted": 0, "held": 0}},
        status=200,
    )
    result = _client().commit("sync-1", [{"type": "namespace", "parentPath": "p", "status": "complete"}])
    assert result["status"] == "committed"
    assert len(responses.calls) == 2


@responses.activate
def test_push_items_retries_on_5xx_then_succeeds(monkeypatch):
    from rwdiscovery import sync as sync_module

    monkeypatch.setattr(sync_module.time, "sleep", lambda _seconds: None)
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/items"
    responses.add(responses.POST, url, status=503)
    responses.add(
        responses.POST, url, json={"seq": 0, "accepted": 1, "created": 1, "updated": 0, "unchanged": 0}, status=200
    )
    client = _client()
    result = client.push_items("sync-1", 0, [{"identity": {}}])
    assert result["created"] == 1
    assert len(responses.calls) == 2  # one failure, one retry


@responses.activate
def test_push_items_raises_after_exhausting_retries(monkeypatch):
    from rwdiscovery import sync as sync_module

    monkeypatch.setattr(sync_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(sync_module, "MAX_RETRIES", 1)
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/items"
    responses.add(responses.POST, url, status=500)
    client = _client()
    try:
        client.push_items("sync-1", 0, [{"identity": {}}])
    except sync_module.SyncClientError:
        pass
    else:
        raise AssertionError("expected SyncClientError")
    assert len(responses.calls) == 2  # initial attempt + 1 retry


@responses.activate
def test_push_items_does_not_retry_on_4xx():
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/items"
    responses.add(responses.POST, url, json={"error": "bad request"}, status=422)
    client = _client()
    try:
        client.push_items("sync-1", 0, [{"identity": {}}])
    except Exception:
        pass
    else:
        raise AssertionError("expected an error")
    assert len(responses.calls) == 1  # no retry on a non-retryable status


@responses.activate
def test_commit_and_abort_bodies():
    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/commit",
        json={"status": "committed", "counts": {"created": 1, "updated": 0, "unchanged": 0, "deleted": 0, "held": 0}},
        status=200,
    )
    result = _client().commit(
        "sync-1", [{"type": "namespace", "parentPath": "kubernetes/clusters/acme-prod-eu", "status": "complete"}]
    )
    assert result["status"] == "committed"

    responses.add(
        responses.POST,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/abort",
        json={},
        status=200,
    )
    _client().abort("sync-1", "fatal error mid-run")
    abort_body = json.loads(responses.calls[-1].request.body)
    assert abort_body == {"reason": "fatal error mid-run"}


@responses.activate
def test_batching_pusher_seq_starts_at_one_for_a_fresh_sync():
    """platform-contract §3: seq numbering starts at 1, not 0 --
    a fresh `BatchingPusher` is constructed for whatever `syncId` `open_sync`
    hands back, so this holds for a truly new sync and for the untouched
    sync a same-run re-open returns alike."""
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/items"
    seqs_seen = []

    def _responder(request):
        body = json.loads(request.body)
        seqs_seen.append(body["seq"])
        return (200, {}, json.dumps({"seq": body["seq"], "accepted": 1, "created": 1, "updated": 0, "unchanged": 0}))

    responses.add_callback(responses.POST, url, callback=_responder, content_type="application/json")

    pusher = BatchingPusher(client=_client(), sync_id="sync-1")
    pusher.add({"identity": {"chain": [{"type": "namespace", "name": "acme-payments"}]}})
    pusher.flush()
    pusher.add({"identity": {"chain": [{"type": "namespace", "name": "acme-other"}]}})
    pusher.flush()

    assert seqs_seen == [1, 2]


@responses.activate
def test_batching_pusher_flushes_at_item_count_limit():
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/items"

    def _responder(request):
        body = json.loads(request.body)
        return (
            200,
            {},
            json.dumps(
                {
                    "seq": body["seq"],
                    "accepted": len(body["items"]),
                    "created": len(body["items"]),
                    "updated": 0,
                    "unchanged": 0,
                }
            ),
        )

    responses.add_callback(responses.POST, url, callback=_responder, content_type="application/json")

    pusher = BatchingPusher(client=_client(), sync_id="sync-1")
    for i in range(201):  # one more than MAX_BATCH_ITEMS (200)
        pusher.add({"identity": {"chain": [{"type": "pod", "name": f"acme-api-{i}"}]}})
    pusher.flush()

    assert len(responses.calls) == 2
    first_body = json.loads(responses.calls[0].request.body)
    assert len(first_body["items"]) == 200
    second_body = json.loads(responses.calls[1].request.body)
    assert len(second_body["items"]) == 1
    assert pusher.totals["created"] == 201


@responses.activate
def test_batching_pusher_flushes_at_byte_limit():
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/items"

    def _responder(request):
        body = json.loads(request.body)
        return (
            200,
            {},
            json.dumps(
                {
                    "seq": body["seq"],
                    "accepted": len(body["items"]),
                    "created": 0,
                    "updated": 0,
                    "unchanged": len(body["items"]),
                }
            ),
        )

    responses.add_callback(responses.POST, url, callback=_responder, content_type="application/json")

    pusher = BatchingPusher(client=_client(), sync_id="sync-1")
    big_value = "x" * (MAX_BATCH_BYTES // 2)
    pusher.add({"document": {"data": {"blob": big_value}}})
    pusher.add({"document": {"data": {"blob": big_value}}})  # pushes the running total over MAX_BATCH_BYTES
    pusher.flush()

    assert len(responses.calls) == 2  # the second add() triggered an eager flush of the first item


@responses.activate
def test_batching_pusher_maps_a_rejected_item_back_to_its_partition_key():
    """platform-contract §3: an unknown type / bad chain is rejected,
    never stored. `discover.py` needs the (type, namespace) partition that
    rejected item belonged to, not just the raw rejected entry, so it can
    report that partition failed at commit."""
    url = "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-syncs/sync-1/items"
    responses.add(
        responses.POST,
        url,
        json={
            "seq": 0,
            "accepted": 1,
            "created": 1,
            "updated": 0,
            "unchanged": 0,
            "rejected": [{"index": 1, "code": "parent_missing", "detail": "namespace not found"}],
        },
        status=200,
    )
    pusher = BatchingPusher(client=_client(), sync_id="sync-1")
    pusher.add({"identity": {"chain": [{"type": "cluster", "name": "acme-prod-eu"}]}})  # index 0, no partition key
    pusher.add(
        {"identity": {"chain": [{"type": "configmap", "name": "acme-app-config"}]}},
        partition_key=("configmap", "acme-payments"),
    )  # index 1 -- the one papi rejects
    pusher.flush()
    assert pusher.rejected == [{"index": 1, "code": "parent_missing", "detail": "namespace not found"}]
    assert pusher.rejected_partitions == {("configmap", "acme-payments"): {"parent_missing"}}


@responses.activate
def test_a_409_outside_open_is_not_reported_as_a_sync_conflict():
    """papi 409s a pack PUT whose type parent/plural would change
    (platform-contract §2) -- that must not read as "sync already open"."""
    responses.add(
        responses.PUT,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-packs/kubernetes",
        json={"errors": [{"path": "types[3].plural", "code": "immutable"}]},
        status=409,
    )
    with pytest.raises(SyncClientError) as excinfo:
        _client().put_pack({"name": "kubernetes", "digest": "d"})
    assert not isinstance(excinfo.value, SyncConflictError)
    assert excinfo.value.status == 409


@responses.activate
def test_put_pack_logs_skipped_entries_but_still_returns_normally(caplog: pytest.LogCaptureFixture):
    """platform-contract §2: an additive type conflicting with an
    existing registration comes back `skipped`, not a failing status --
    logged so it's visible, never raised."""
    responses.add(
        responses.PUT,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-packs/kubernetes",
        json={
            "name": "kubernetes",
            "digest": "d",
            "registered": True,
            "counts": {},
            "skipped": [{"type": "widget.acme.io", "reason": "plural_conflict"}],
        },
        status=200,
    )
    with caplog.at_level(logging.WARNING, logger="rwdiscovery.sync"):
        result = _client().put_pack({"name": "kubernetes", "digest": "d"})
    assert result["digest"] == "d"
    assert any("widget.acme.io" in r.message and "plural_conflict" in r.message for r in caplog.records)


@responses.activate
def test_put_pack_with_no_skipped_entries_logs_nothing(caplog: pytest.LogCaptureFixture):
    responses.add(
        responses.PUT,
        "https://papi.acme.internal/api/v4/workspaces/acme-workspace/resource-packs/kubernetes",
        json={"name": "kubernetes", "digest": "d", "registered": True, "counts": {}},
        status=200,
    )
    with caplog.at_level(logging.WARNING, logger="rwdiscovery.sync"):
        _client().put_pack({"name": "kubernetes", "digest": "d"})
    assert caplog.records == []


def test_the_token_never_appears_in_a_repr():
    assert "jwt-token" not in repr(CRED)
    assert "jwt-token" not in repr(_client())
