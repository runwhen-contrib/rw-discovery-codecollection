---
name: triage-k8s-discovery
description: Use when a k8s-discovery `discover` run failed or timed out, resources are missing or were unexpectedly deleted from the platform's resource inventory, a sync's partitions come back `forbidden` or `excluded`, a sync commit is failing, pack registration is rejected, a `cli` task command is refused or returns nothing, or the image/label/schema CI checks are failing. Covers the `connect`/`discover`/`cli` tasks, the enumerate -> sanitize -> sync pipeline, the Kubernetes pack (types, facets, dependency rules, the `cli` allow-list), kubeconfig credentials, and the schema/manifest/image release pipeline.
---

# Triage: k8s-discovery runs and the `cli` task

Load this when a `k8s-discovery` capability run (or the image that ships it) is
misbehaving and you need to find *where* fast. `docs/platform-contract.md` is the design
doc this skill is a triage index into -- read it for the parts marked "see the contract"
below. `README.md` is the public-facing walkthrough of the same material.

## 1. Mental model

Three tasks, declared in `capabilities/k8s-discovery/manifest.yaml`:

- **`connect`** (setup, runs once per request) -- materialises the `kubeconfig`
  credential into an API client (`rwdiscovery/connect.py`), confirms the cluster is
  reachable, and reads `serverVersion` + `clusterUid`. If this fails, `discover`/`cli`
  never start.
- **`discover`** -- enumerates the cluster and pushes it to the platform's resource
  inventory. Writes; every other task is read-only.
- **`cli`** -- one allow-listed, read-only `kubectl` command, exec'd for real and
  returned synchronously. The earlier `inspect` task (a narrower, sanitized `get`/
  `describe` over the Kubernetes API) was retired in its favour -- `cli` is now the
  agent's one read path into a cluster.

`discover`/`connect` never shell out; every read goes through the Kubernetes API
directly (`rwdiscovery/k8s_client.py`'s `K8sClient`, which refuses to issue anything but
a `GET` -- `ReadOnlyViolationError` otherwise). `cli` is the one exception.

### The `discover` pipeline (`rwdiscovery/discover.py`'s `run_discover`)

1. **Register the pack** -- `put_pack()` PUTs `packs/kubernetes/pack.yaml`'s static part
   (types, facet definitions, dependency rules) plus this cluster's own additive part
   (CRDs, aggregated APIs). The static part is idempotent by digest -- registering it
   unchanged is a no-op. An additive type conflicting with an existing registration comes
   back in the response's `skipped` list, logged by `sync.py` and not fatal; any item of
   that type is later rejected when pushed, failing only its own partition.
2. **Open a sync** for this cluster's scope (`scopePath = kubernetes/clusters/<name>`).
3. **Push items in batches** -- cluster, then in-scope namespaces, then everything else
   (`BatchingPusher`, at most 200 items / 2 MB per push, well inside the platform's own
   500-item / 5 MB ceiling). Ephemeral types (pods, ReplicaSets, EndpointSlices, events,
   leases, ...) are never pushed as resources, but pods/ReplicaSets/EndpointSlices/events
   are still read to compute **rollups** (pod counts/restarts, endpoint readiness,
   CronJob run history, cluster version) attached to the resources they belong to. A
   `403`/error reading a rollup source is never treated as "zero of that" -- the facet is
   omitted, and the summary's `rollupSourcesUnavailable` records which source, per
   namespace.
4. **Commit** with one partition per `(type, parentPath)` actually attempted:
   - `complete` -- the only status the platform ever sweeps against (deletes everything
     of that type under that parent it did NOT see this run, cascading to descendants and
     edges). A partition with even one rejected item is reported `failed`, never
     `complete`, regardless of how many other items landed fine.
   - `forbidden` -- the listing itself 403'd; never reported as `complete` with a zero
     count instead, since "not readable" is a different claim than "confirmed empty".
   - `excluded` -- a namespace `namespaces`/`excludeNamespaces` left out of scope (for the
     namespace itself and every namespaced type in it). Never swept -- narrowing scope
     stops refreshing that namespace, it does not delete what was already synced for it.
   - `failed` -- a listing error that wasn't a 403.
   A **mass-delete guard** on the platform side holds a sync (`held`, not `committed`)
   rather than deleting more than `max(25% of active resources under scopePath, 50)` --
   see the contract §3.
5. Any exception once the sync is open aborts it (best-effort) and re-raises, rather than
   leaving it to expire on its own lease.
6. Returns `rw.discovery_summary.v1` (see "healthy run" below) -- **no bulk data ever
   rides this output**; everything else goes straight to the platform through the sync
   API.

### The pack (`packs/kubernetes/pack.yaml`)

Registered at the start of *every* `discover` run. Carries: facet definitions
(`k8sSummary`, `k8sWorkload`, `k8sPods`, `k8sConfigData`, `k8sRbac`, ... -- projections or
rollups over the sanitized document), dependency rules (`reference`, `owner_reference`,
`label_selector`, `field_join`, `path_template`, `dns_reference` strategies), an `access`
block (`typeRead`/`permissions`/`featureGroups` -- what "read type T" means in this
platform's own RBAC terms, feeding a per-cluster Access view), and the `cli:` block (see
§3). Type specs are NOT in this file -- they come live from `rwdiscovery/chain.py`'s
builtin table plus discovered CRDs (`rwdiscovery/packbuild.py`), so there's exactly one
place that knows the Kubernetes type table.

## 2. Credentials

Declared in `manifest.yaml`'s `needs.credentials`:

| local name | kind | access | shape |
|---|---|---|---|
| `kubeconfig` | `k8s.kubeconfig` | read | the kubeconfig YAML, as a string |
| `resourceSync` | `runwhen.resourceSync` | write | `{"apiBaseUrl", "token", "workspace", "expiresAt"}` -- a lease-scoped token valid only on pack-registration/sync-protocol routes |

`cli` only ever calls `ctx.credential("kubeconfig")` -- it never touches
`resourceSync`, so it can be exercised without a platform endpoint at all (§4).

**`context` input.** `discover` and `connect` accept an optional `context` naming one of
the `kubeconfig` credential's other contexts, instead of its current-context -- lets one
kubeconfig serve more than one cluster. It's checked against the kubeconfig's own
`contexts:` list before anything else (`rwdiscovery/credentials.py`'s
`_require_known_context`); an unknown context fails immediately with a `KubeconfigError`
naming it. `cli` has no `context` input of its own -- it always runs against the
kubeconfig's current-context, same as a bare `kubectl` would.

**In-cluster auth.** The manifest declares `execution.serviceAccountToken: true`, so for
an in-cluster run the platform hands this capability a kubeconfig pointing at the
executor pod's own projected, rotating ServiceAccount token and CA -- nothing for an
operator to generate. An **exec credential plugin** kubeconfig (`gke-gcloud-auth-plugin`,
`aws eks get-token`, `kubelogin`, ...) is **not supported**: the image ships no shell
tools or cloud CLIs, so loading it fails as a `KubeconfigError`.

**RBAC expectations.** There is no separate, scoped-down discovery credential -- the
kubeconfig is ordinarily the same one a workspace's other Kubernetes tasks use, and it is
on this code (`K8sClient`'s GET-only chokepoint), not the credential's own RBAC, to
guarantee discovery never writes. A common minimal grant is a **namespace-scoped `view`
role**: Kubernetes' own built-in `view` ClusterRole deliberately excludes Secret reads,
and a namespaced RoleBinding can never reach a cluster-scoped kind (Nodes, ClusterRoles,
a cluster-wide namespace `list`, ...) at all -- so under that grant, Secrets and every
cluster-scoped type report their partition `forbidden`, never a false "zero of that
type" (the whole point of `forbidden` vs. `complete`/count-0, contract §3). When a
cluster-wide namespace `list` is itself forbidden, an explicit `namespaces` input still
gets each named namespace fetched individually by `GET` -- a namespace even that can't
reach still gets pushed as an identity-only **stub** so its children have a parent.
Whatever Secrets a broader role *does* let through sync normally, sanitized down to
metadata/type/key-names only (`rwdiscovery/sanitize.py` -- `data`/`stringData` never
leave the cluster).

## 3. The `cli` task

`packs/kubernetes/pack.yaml`'s `cli:` block is the allow-list: a closed `verbs` list
(`get`, `describe`, `logs`, `top`, `events`, `explain`, `api-resources`, `api-versions`,
`version`, `auth can-i`, `rollout history`), a `denyFlags` list (credential/context
overrides, `-f`/`--filename`, `--watch`/`--follow`/`-i`/`-t`, ...), `sensitiveTypes:
[secret, secrets]` (only the default table, `-o name`, or `-o wide` -- never a full
object dump), and `output: {defaultBytes: 16384, maxBytes: 65536, timeoutSeconds: 30,
maxTimeoutSeconds: 60}`.

**`rwdiscovery/cli.py`'s `validate()` re-validates every request from scratch** against
this same block (loaded via `packbuild.load_pack_yaml()["cli"]`) -- the platform's own
copy of these rules exists only for early, helpful errors; this capability's is
authoritative, and `run_cli()` never execs anything `validate()` rejects. Order: split
argv (drop a leading `kubectl`) -> reject any shell metacharacter in any token -> match
the verb -> reject a denied flag -> for `get`, check the resource arg against
`sensitiveTypes` -> resolve pseudo-flags (`--grep`, `logs`' `--tail`/`--limit-bytes`
defaults) last, after everything else has validated the command as given.

**A refusal** (`rw.cli_result.v1` with `rejected` set): `exitCode: -1`, empty
`stdout`/`stderr`, `rejected: {"reason": "<code>", "hint": "<message>"}`. `reason` is one
of `empty`, `no-shell`, `verb-not-allowed`, `flag-not-allowed`, `sensitive-type`,
`invalid-grep` -- `subprocess` is never invoked in this case. A **non-rejected** result
with a non-zero `exitCode` and `stderr` populated is a real `kubectl` failure that passed
validation (RBAC, not-found, ...), not a refusal.

**Output bounds.** `maxBytes`/`timeoutSeconds` request inputs are clamped to the pack's
`output.maxBytes`/`output.maxTimeoutSeconds` ceilings (`resolve_max_bytes`,
`resolve_timeout_seconds`). `truncated: true` means either the wall-clock timeout fired
(`timeoutSeconds + 2`s grace) or `maxBytes` of *matching* (post-`--grep`) stdout was
reached; stderr is capped independently at a fixed 4 KB. `kubectl` runs as a real
subprocess (no shell) with a scrubbed environment (`PATH`/`HOME`/`KUBECONFIG` only).

**The image ships a pinned `kubectl`** (`Dockerfile.k8s-discovery`'s `kubectl` build
stage): currently **v1.37.1**, fetched and sha256-verified per-architecture at build
time -- used only by `cli`; `discover`/`connect` talk to the Kubernetes API over HTTP
directly and never invoke this binary.

## 4. Running locally & the test suite

`cli` needs only the `kubeconfig` credential, so it can be smoke-tested against any
cluster your own kubeconfig reaches, without a platform endpoint:

```
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"

cat > /tmp/credentials.json <<JSON
{"kubeconfig": "$(cat ~/.kube/config | sed 's/"/\\"/g')"}
JSON
cat > /tmp/request.json <<'JSON'
{"version": 1, "setup": {"task": "connect", "inputs": {}},
 "tasks": [{"task": "cli", "inputs": {"clusterName": "dev", "argv": ["get", "namespace", "kube-system"]}}]}
JSON
rwtask run capabilities/k8s-discovery --request /tmp/request.json --credentials /tmp/credentials.json
```

`discover` additionally needs the `resourceSync` credential (a real, likely local/dev
platform endpoint) to do anything beyond registering the pack. The fast, fully offline
way to exercise `discover` end to end is `tests/test_discover_e2e.py` -- a small
synthetic cluster (`tests/fakes.py`'s in-process fake Kubernetes API) discovered against
a faked platform HTTP API, asserting push order, batching, sanitization, rollups, and
commit partitions.

```
make test        # python -m pytest -q -- everything, offline, against acme-* fixtures
make lint         # ruff check .
make fmt-check    # ruff format --check .
make schemas      # regenerate capabilities/k8s-discovery/schemas/*.json from rwdiscovery.models
make vectors      # pack.yaml JMESPath validation + chain vectors, in isolation
```

**Schema export, immutability and the docstring gotcha.** Task output schemas
(`capabilities/k8s-discovery/schemas/*.json`) are generated, not hand-written --
`scripts/export_schemas.py` runs `pydantic`'s `TypeAdapter(...).json_schema()` over each
model in `rwdiscovery/models.py` (`DiscoverySummary`, `K8sObjectResult`, `CliResult`) and
writes `<name>.v<SCHEMA_VERSION>.json`, never overwriting an already-published file. CI's
`test` job runs `export_schemas.py` and then `git diff --exit-code` against the checked-in
files ("Verify checked-in schemas match the models") -- **a model's own docstring is
baked into its exported schema's `description` field**, so editing a docstring *without*
bumping that model's `SCHEMA_VERSION` fails this check exactly like a real shape change
would. The fix is always the same: bump `SCHEMA_VERSION` next to the model and re-run
`make schemas`, which publishes a new `<name>.v<N+1>.json` -- the old file is never
edited. `scripts/check_schema_immutability.py --base <ref>` (CI: "Check published schemas
are versioned and immutable") separately enforces that every versioned file that existed
at the base ref stays byte-for-byte (as canonical JSON) identical and is never deleted --
this is why `K8sObjectResult`/`schemas/k8s_object.v1.json` still exist even though
`inspect`, the task that used to produce them, is gone: **a published schema file can
never be deleted**, retired task or not.

## 5. Image and release

There is no `image:` key in `manifest.yaml` -- an image cannot know its own digest.
Instead, every pushed image carries the base64 of its own `manifest.yaml`, verbatim, as
the OCI label `com.runwhen.capability.manifest.v1`; a second label,
`com.runwhen.capability.schemas.v1`, carries a base64 JSON map of every file under
`schemas/` (not just the ones the current manifest references). Both are computed by
`scripts/manifest_label.py` and baked in by `Dockerfile.k8s-discovery`'s build args -- the
codecollection catalog reads them straight off the pushed image's config blob to learn
the capability's id, version, full manifest, and every schema version it might need to
resolve an older run's result against, never from a separate build artifact.

**Tags** (`.github/workflows/build-push.yaml`):

| trigger | canonical tag | moving alias |
|---|---|---|
| push to any branch | `<sanitized-ref>-<sha7>` | `<sanitized-ref>` (+ `latest` if the branch is `main`) |
| pull request | `pr-<n>-<sha7>` | `pr-<n>` |
| semver tag (`v1.2.3`, matching `v[0-9]+.[0-9]+.[0-9]+*`) | the tag itself, no `-<sha7>` suffix | none -- no `latest`, no branch alias |

The catalog's `stable` channel resolves to the highest semver tag published this way. A
fork's pull request never pushes (GHCR login needs write-scoped credentials a fork PR's
token doesn't get) -- it still builds and runs the `test`/smoke-test jobs, just with
`should_push: false`.

## 6. Symptom -> first check -> likely cause -> fix

| Symptom | First check | Likely cause | Fix |
|---|---|---|---|
| **`discover` run failed or timed out** | Did `connect` (setup) succeed at all -- are `serverVersion`/`clusterUid` populated? | `connect` fails fast on an unreachable cluster or an unknown `context` (`KubeconfigError`) before `discover` ever starts; or the platform's sync API returned 5xx past `SyncClient`'s 4 retries (`SyncClientError`); or a very large cluster approached `manifest.yaml`'s `requestTimeoutSeconds: 1500` ceiling | Fix the kubeconfig/context first if `connect` itself failed; check the platform's own health for a `SyncClientError`; narrow scope with `namespaces`/`excludeNamespaces` for a cluster this large |
| **Resources missing or unexpectedly deleted** | The `rw.discovery_summary.v1` output's `partitions` counts and `counts.deleted`; was this namespace ever `excluded` instead of `complete`? | A genuine `complete` partition sweeps every resource of that `(type, parentPath)` not seen this run -- normal if the resource was actually removed from the cluster; `excluded`/`forbidden`/`failed` partitions are never swept, so real deletion always traces back to a `complete` one | Confirm the partition was really `complete`; if the platform reports the sync ended `held` rather than `committed`, the mass-delete guard fired and nothing was actually deleted yet (contract §3) |
| **Partitions reported `forbidden`/`excluded`** | The summary's `partitions.forbidden` count and `rollupSourcesUnavailable` map (keyed by namespace, `""` = cluster scope) | `forbidden` = a listing 403'd (RBAC gap); `excluded` = `namespaces`/`excludeNamespaces` narrowed scope on purpose | For `forbidden`, grant the read the pack's `access.typeRead`/`featureGroups` name for that type; for `excluded`, confirm the input was intentional -- it is non-destructive either way |
| **Sync commit failing** | The exception around `sync_client.commit(...)` in the run's error, or the summary's `partitions.failed` entries and their `reason` string | An item was rejected while pushing (unknown type, missing parent pushed out of order, a pack-`skipped` type) -- that whole `(type, parentPath)` reports `failed`, "items rejected: `<codes>`"; or the platform 5xx'd past retries | Push order must be cluster -> namespaces -> rest (already how `discover.py` orders it -- check for a custom caller that doesn't); check `pack.yaml` for the skipped/conflicting type |
| **Pack registration rejected** | `put_pack()`'s response `skipped` list -- logged as `pack registration skipped type %s: %s` | An additive type (CRD/aggregated API) whose parent or plural conflicts with an already-registered type; a static-part JMESPath expression outside the platform's structural limits (length/AST size/nesting/multi-select width) | Rename/adjust the conflicting type; run `make vectors` locally first -- `tests/test_pack_yaml.py` compiles every JMESPath expression and checks every strategy/edgeType against the pack's own closed vocabulary before it ever reaches the platform |
| **`cli` command refused or returning nothing** | `rw.cli_result.v1`'s `rejected` field -- set (with `exitCode: -1`) means validation refused it before exec; `null` with a real `exitCode`/`stderr` means it ran | `rejected.reason` (`verb-not-allowed`, `flag-not-allowed`, `sensitive-type`, `no-shell`, `invalid-grep`, `empty`); "nothing" with no rejection can be a legitimately empty result or `truncated: true` (timeout or `maxBytes` hit) | Check `rejected.hint`; adjust `argv` to `packs/kubernetes/pack.yaml`'s `cli` block; raise `maxBytes`/`timeoutSeconds` inputs if truncated (both still clamp to `output.maxBytes: 65536` / `output.maxTimeoutSeconds: 60`) |
| **Image / label / schema CI failing** | Which step failed: "Verify checked-in schemas match the models", "Validate the capability manifest", "Validate the output schemas the manifest references", "Check published schemas are versioned and immutable", or the build job's smoke test | A `rwdiscovery/models.py` edit (shape *or* docstring) without bumping `SCHEMA_VERSION`; a hand-edited/deleted file under `schemas/`; `manifest.yaml` missing a required key or flipping `discover`'s/`cli`'s `readOnly`; `Dockerfile.k8s-discovery`'s `KUBECTL_VERSION` and its per-arch sha256 args out of sync | Bump `SCHEMA_VERSION` and run `make schemas` instead of editing the old file; never hand-edit `schemas/*.json`; run `make lint`/`make fmt-check` and `python3 scripts/manifest_label.py` locally before pushing |

## 7. What a healthy run looks like

- **`connect`** returns non-empty `serverVersion` and (RBAC permitting) a non-empty
  `clusterUid`.
- **`discover`**'s `rw.discovery_summary.v1`: `partitions.failed` and `partitions.forbidden`
  are `0` against a fully-privileged kubeconfig; `rollupSourcesUnavailable` is `{}`;
  `counts` shows a mix of `created`/`updated`/`unchanged` and `deleted: 0` on a steady
  cluster with nothing removed. A re-run against an unchanged pack logs no
  `pack registration skipped type ...` warnings (registration was a no-op by digest).
- **`cli`**: `rejected: null`, `truncated: false`, `exitCode` matching what a bare
  `kubectl` invocation would have returned.
- **CI**: the `test` job's schema-diff step passes with no `git diff` output; the build
  job's smoke test log contains `serving capability 'k8s-discovery' ... from
  capabilities/k8s-discovery` (proof `rwtask serve` resolved this exact capability, not
  just that the binary started) and confirms the shipped `kubectl --client` version
  matches `Dockerfile.k8s-discovery`'s pinned `KUBECTL_VERSION`.

## Related skills

- `triage-resource-inventory` (in the RunWhen platform's own repository) -- the
  platform-side half of the sync path: how packs, syncs, items and partitions are stored
  and queried once `discover` pushes them.
- `triage-capability-runs` (in the RunWhen platform's own repository) -- the
  capability-run queue and workspace capability bindings that schedule a `discover`/`cli`
  run in the first place.
- `triage-capability-runs` (in the RunWhen runner's own repository) -- the lease and
  executor-pod path a `discover`/`cli` request actually rides once it leaves the
  platform: pool lifecycle, credential resolution, and the stateless synchronous path the
  platform's own CLI feature uses to reach `cli`.
