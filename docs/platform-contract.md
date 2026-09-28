# The platform contract

This describes the interface `k8s-discovery` implements against the RunWhen platform's API
("papi"): how a capability identifies the resources it finds, registers the types/facets/rules
that describe them, pushes them in bulk, and is handed the credentials it needs to do any of that.

It is written for anyone extending or reviewing this capability, or building another one against
the same interface -- it does not cover papi's internals (storage, auth implementation, query
service) beyond what a capability author needs to know. Sections are numbered so code comments in
this repo can cite them briefly, e.g. `platform-contract §3`.

This document describes the interface as this capability actually uses it today. Where the
platform's interface is broader than what `k8s-discovery` needs, only the parts this repo touches
are covered.

## 1. Resource identity

Every resource the platform tracks has a **path**: a typed, hierarchical identifier built from a
**chain** of `{type, name}` pairs, ancestor-first, ending in the resource itself.

```
path = platform "/" plural(t0) "/" enc(n0) "/" ... "/" plural(tN) "/" enc(nN)
```

- `platform` is a short lowercase string identifying the source system (`kubernetes`, `github`,
  ...). Type names and their plurals both match `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`.
- Each type in the chain contributes its **plural** form (declared on its type spec, §2) and the
  encoded **name** of that particular instance.
- `enc(name)` applies the type's declared name case (`lower` lowercases the name; `preserve` keeps
  it as given), Unicode-normalizes to NFC, then percent-encodes (uppercase hex) the characters
  `: / % # ?`, whitespace, and control characters -- everything else passes through unchanged.
  Kubernetes names are declared `preserve`: DNS-1123 object names are already lowercase, but
  RBAC/kubeconfig-derived names (cluster names, in particular) are not guaranteed to be.
- `chain[0]` must be a **root** type -- one with no declared parent. Every following element's
  type must be the declared parent of the next element's type. A workspace can have more than one
  kind of root (Kubernetes' `cluster` and GitHub's `owner` are both roots, in their own platforms).
  Depth is bounded (8 elements).
- **parentPath** is the path of every chain element except the last (`None` for a root resource).
- A **URN** (`rw:<platform>:<enc(n0)>/.../<enc(n(N-1))>:<tN>/<enc(nN)>`) is derived from the same
  chain and kept for backward compatibility with older, pre-path identifiers; the path is the
  identifier a producer and a reader should actually use.

The platform is the **sole minter** of both path and URN. A capability never builds either string
itself -- it only ever sends a typed chain (§3's `identity.chain`), and papi computes the path/URN
from it, validating every step above (unknown type, wrong parent, non-root first element, empty or
over-length name) and rejecting the item if any check fails.

Example: a cluster's own path is `kubernetes/clusters/<clusterName>`; a Deployment inside it is
`kubernetes/clusters/<clusterName>/namespaces/<namespace>/deployments/<name>`.

## 2. Type specs and packs

A **pack** registers everything the platform needs to know about a platform's resource types in
one call:

```
PUT /api/v4/workspaces/{workspace}/resource-packs/{name}
body  {name, version, platform,
       types: [TypeSpec], facetDefinitions: [FacetDefinition], dependencyRules: [DependencyRule],
       additiveTypes?: [TypeSpec], additiveFacetDefinitions?: [FacetDefinition]}
200   {name, version, digest, registered: bool, counts: {...}, skipped?: [{type, reason}]}
```

The body has two parts:

- The **static** part -- `types`, `facetDefinitions`, `dependencyRules` -- must be identical for
  every instance this pack is registered against (every cluster, for a Kubernetes pack). The
  platform computes a canonical digest over this part alone (a hash of its sorted-key, compact
  JSON) and returns it; registering it again unchanged is a no-op (`registered: false`), and this
  is what makes `discover` safe to re-register the pack on every run without cost.
- The **additive** part -- `additiveTypes`, `additiveFacetDefinitions` -- carries whatever *this
  particular instance's own discovery* found: CustomResourceDefinitions, aggregated APIs, anything
  not already covered by the static part. Additive entries are upserted independently of the
  digest and are never removed just because a later registration from a different instance omits
  them. An additive type whose parent or plural would conflict with an already-registered type is
  **skipped** (reported by name and reason in the response, not a failure of the whole call); any
  resource later pushed under a skipped type is rejected by the sync API (§3), failing only that
  type's own partition, never the whole run.
- A workspace may register only **one** facet-definition row per `(key, origin)` pair. An additive
  contribution to an existing facet (for example, a CRD's own printer columns extending the
  generic `k8sSummary` facet) must be merged into that facet's `expressionByType` map by the
  platform, not registered as a second, separate definition sharing the same key.

Shapes:

```
TypeSpec        {type, plural, parent: str | null, displayName, category?, ephemeral: bool,
                 nameCase: "lower" | "preserve", aliases: [str], native: {}}
FacetDefinition {key, title, description, appliesTo: {platform, types: [str] | ["*"]},
                 populator: {kind: "projection" | "rollup" | "task" | "agent",
                             expression?: str, expressionByType?: {type: str}, sources?: [str], task?: {}},
                 schema?: JSONSchema, volatility: "config" | "state", ttlSeconds?: int}
DependencyRule  {id, description, edgeType, from: {platform, types: [str]}, to: {platform, types: [str]},
                 strategy, params: {}, direction: "forward" | "reverse", confidence?: float}
Access          {typeRead: {native: {}, required: [str], sensitive: [str]},
                 permissions: [{id, title, description?, required: bool, native: {}}],
                 featureGroups: [{id, title, description?, types: [str], facets: [str], rules: [str]}]}
```

- `parent` names another type registered in the same platform, or is `null` for a root type (§1).
- A facet's `populator.expression` is a JMESPath expression, evaluated against the resource's
  sanitized `document` merged with its `status` (a projection can read either, or fields from
  both in the same expression). `expressionByType` overrides the generic `expression` for
  specific types -- the mechanism a CRD's own printer columns use to extend a generic facet like
  `k8sSummary` without a bespoke facet per CRD. `populator.sources` -- allowed only when
  `populator.kind == "rollup"` -- names the types a rollup is actually computed from (e.g.
  `k8sPods: [pod, replicaset]`); a rollup source is a "read" need of the facet exactly like a
  type read (used to derive per-facet access status, below).
- An optional top-level **`access`** block (access-phase1 design) declares how this platform's own
  credential model expresses "read type T" (`typeRead.native`, a template rendered per type by
  substituting `{type}`/`{plural}`/`{apiGroup}`/`{apiVersion}`/`{kind}` from the type row -- papi
  never interprets the result), any other named `permissions` that aren't a type read (e.g. reading
  the API server's own version), and optional, human-sized `featureGroups` papi derives a
  per-cluster Access view from. Validation (422 with every violation, same as the rest of pack
  validation): `typeRead.native` and each permission's `native` must be a JSON object no more than
  4 KB serialised, with no placeholder outside the five named above; `typeRead.required`,
  `typeRead.sensitive` and every facet's `populator.sources` must name a type this pack's own
  static `types` declares (an ERROR otherwise); a feature group's `types` may additionally name a
  type only a per-cluster CRD registers additively -- a WARNING, not an error, riding back in a
  new, optional `notes: [{kind: "access", ref, reason}]` list alongside the existing `skipped`
  list; a feature group's `facets`/`rules` must be facet keys/rule ids this pack declares;
  permission ids are unique among themselves, as are feature-group ids. A pack that omits `access`
  registers exactly as before, with no access view.
- Every edge a dependency rule produces reads **"`from` depends on `to`"**. `direction: reverse`
  swaps the two ends when the edge is actually emitted, so a rule can still be authored in the
  more natural "who points at whom" direction.
- The strategy vocabulary is closed:

  | strategy | what it matches |
  |---|---|
  | `reference` | one or more JMESPath-derived values on the `from` resource, matched against a target `scope`; an optional `namePattern` builds a name from a template, an optional `typeFrom` resolves a per-value type alias (e.g. an autoscaler's `scaleTargetRef.kind`) |
  | `owner_reference` | Kubernetes-style owner references, matched by `providerUid`; when the owner hasn't been synced yet, falls back to a same-parent, dangling edge built from the reference's own kind/name rather than dropping it |
  | `label_selector` | a selector (JMESPath) against the target's labels; `params.emptySelector: "none" \| "all"` (default `"none"`) controls whether an empty selector matches nothing or everything, matching Kubernetes' own selector semantics where each is used |
  | `field_join` | an equality join between one JMESPath-derived value on each side |
  | `path_template` | a regex match against a JMESPath-derived value, whose named capture groups are percent-encoded (§1's `enc()`) and substituted into a path template; the reserved placeholders `{root}` and `{parent}` expand to the `from` resource's own root path and parent path (whole paths, never encoded; a capture group may not use either name), so a template can anchor a target in the source's own cluster or namespace without hardcoding it |
  | `dns_reference` | a DNS mention (host, `<service>:<port>`) resolved against resources already known in scope; unlike every other strategy this one never dangles -- an unresolved mention produces no edge at all, since a bare hostname carries no type information to build a target path from. An optional `params.hostKeys` regex names the env-var / ConfigMap keys whose whole value may be a bare `<service>` or `<service>.<namespace>` (e.g. `DATABASE_HOST=pgbouncer`); without it only FQDNs, URLs and `<service>:<port>` count |

  `scope` (used by `reference`, `label_selector`, `field_join`) is one of `sameParent` (the same
  immediate parent -- e.g. the same namespace), `sameRoot` (the same chain root -- e.g. the same
  cluster), or `any`. `confidence` is optional per rule; when absent, the strategy's own default
  applies (`dns_reference` defaults to `0.6`; every other strategy defaults to `1.0`).
- Every JMESPath expression (a facet's projection or a rule's parameters) is validated at
  registration time under structural limits (bounded length, AST size, nesting depth, and
  multi-select width) so a pathological expression is rejected up front rather than failing, or
  running away, at evaluation time later.

## 3. Sync protocol

A **sync** is the unit of a bulk push: `open`, one or more `items` batches, then `commit` (or
`abort` on failure).

```
POST /resource-syncs
  {source, scopePath, mode: "full", capabilityRunUuid?, configHash?, pack?: {name, digest}}
  201 {syncId, leaseExpiresAt}
  409 {syncId, leaseExpiresAt, capabilityRunUuid} when an unexpired sync is already open for this (source, scopePath)
POST /resource-syncs/{syncId}/items
  {seq: int, items: [Item]}          -- at most 500 items / 5 MB per call
  200 {seq, accepted, created, updated, unchanged, rejected: [{index, code, detail}]}
POST /resource-syncs/{syncId}/commit
  {partitions: [{type, parentPath, status: "complete" | "failed" | "forbidden" | "excluded",
                 count?: int, reason?: str}], stats?: {}}
  200 {status: "committed" | "held", counts: {created, updated, unchanged, deleted, held}}
POST /resource-syncs/{syncId}/abort     {reason}   -> 200
POST /resource-syncs/{syncId}/release              -> 200 (executes a held sync's deletes)
```

- **Items.** `{identity: {platform, chain}, providerUid?, displayName?, labels: {}, document: {},
  status?: {}, rollups?: {facetKey: value}}`. `document` is the sanitized resource *without* its
  status; `status` is sanitized and stored separately (facet expressions, §2, may read either, or
  both together). `rollups` is a map of facet key to precomputed value, stamped onto the resource
  as a facet value from this discovery run.
- **Minting and ordering.** Every item's path is minted from its chain against the workspace's
  registered types (§1, §2). An unknown type or an otherwise invalid chain is `rejected`, never
  stored. A resource's parent must already exist -- from an earlier batch, or earlier in the same
  batch -- so a producer must push roots first, then their immediate children, and so on; a
  missing parent is its own rejection code. `seq` starts at **1** for a fresh sync and increments
  by one per batch; replaying the same `seq` with the same items returns the stored response
  rather than re-applying it, making a retried batch safe, while replaying it with *different*
  items is rejected as a conflict.
- **Partitions and their statuses.** At commit, the caller reports one partition per
  `(type, parentPath)` it attempted to fully enumerate. `complete` is the only status the platform
  ever sweeps against. `forbidden` means the listing itself could not be read (a permissions
  gap) -- it must never be reported as `complete` with a zero count instead, because "not
  readable" is a different claim than "confirmed to have zero members". `failed` and `excluded`
  are likewise never swept. A partition is never swept as `complete` if even one of its items was
  rejected on the way in, regardless of what the caller reports at commit time.
- **Rollup source reads still report a partition.** A type `k8s-discovery` reads only to compute a
  rollup facet value and never pushes as an item in its own right (`pod`, `replicaset`,
  `endpointslice`, `event`, read once per in-scope namespace) is reported at commit exactly like
  any other fully-enumerated `(type, parentPath)` -- the read already happened, so its outcome is
  reported the same way; a `complete` one there simply sweeps nothing, since nothing of that type
  is ever stored.
- **Mark-and-sweep, with descendant cascade.** For each `complete` partition, the platform
  soft-deletes every active resource of that type, under that `parentPath`, within the sync's
  `scopePath`, that this sync did not touch. Soft-deleting a resource also soft-deletes every
  active descendant under its path and every edge to or from it -- a sweep of a namespace's
  Deployments does not leave orphaned ReplicaSet-derived edges behind, for instance.
- **The mass-delete guard.** If a sweep would remove more than `max(25% of the active resources
  under scopePath, 50)`, nothing is deleted: the sync ends as `held` instead of `committed`, with
  the resources that would have been deleted recorded against it. A held sync's deletes only
  happen once it is explicitly released (`/release`, admin-only) -- or automatically, the next
  time an ordinary sync of the same scope would delete exactly the same set, which lets a
  transient, wrongly-scary sync self-clear on the next successful run without an operator's
  intervention every time.
- **Re-open and 409 semantics.** Opening a sync for a `(source, scopePath)` that already has an
  unexpired open sync normally fails with `409`. The one exception: if the new request names the
  *same* `capabilityRunUuid` as the existing open sync, the platform treats it as the same
  producer retrying a lost response rather than a conflict -- it returns the existing sync
  unchanged (`200`) if it hasn't received any items yet, or aborts the stale one and opens a fresh
  sync (`201`) if it has. Either way the caller ends up with a `syncId` it can safely push against
  from `seq` 1, with no separate "adopt" call needed.
- **Idempotent commit/abort.** Replaying `commit` or `abort` against a sync that has already
  reached that terminal state returns the previously stored outcome rather than erroring --
  useful for a producer that lost the response to its own commit call.
- **`capabilityRunUuid`.** When a sync is opened as part of a scheduled or agent-triggered
  capability run, the platform ties the sync to that run. If the run itself fails or is otherwise
  terminated before the sync reaches `committed`, the platform aborts the sync (no deletes) rather
  than leaving it to expire on its own lease.
- **Scoping under the sync credential.** A sync opened with the `resources:sync` credential (§4)
  is further restricted: every item pushed to it must fall under the sync's own `scopePath` and
  must be of a type registered by a pack (never one of the platform's own built-in, global
  types) -- anything else is rejected as out of scope.
- A lease has a bounded lifetime; an open sync that is never committed, aborted, or otherwise
  touched expires on its own after that window, with no deletes performed.

## 4. Credentials

A capability declares what it needs in its manifest's `needs.credentials`; the platform resolves
each declared kind at lease time and hands the task the resolved value directly -- the task itself
never learns a secret's name, or where it is actually stored.

- **`k8s.kubeconfig`** -- the kubeconfig, as a plain YAML string, for the cluster this capability
  run targets. It is bound the same way any other credential an SLX/automation uses is bound (a
  reference to a workspace-held secret, or to a Kubernetes Secret local to wherever the runner
  executes) -- or, for a capability whose manifest declares `execution.serviceAccountToken: true`
  (as this one does), to the executor pod's own ServiceAccount token; which of those the platform
  resolves is an implementation detail this capability does not need to know or branch on -- it
  always receives the same plain string either way. There is no separate, scoped-down discovery
  credential: this is ordinarily the same kubeconfig a workspace's Kubernetes tasks use, so it is
  on this capability, not that credential's own RBAC, to guarantee it only ever reads. `discover`
  builds its API client through `rwdiscovery/k8s_client.py`'s `K8sClient`, the only place this
  package calls the Kubernetes API library directly, which refuses to issue anything but a `GET`.
  `cli` (§7) is the one exception to "never shells out": it execs the real `kubectl` binary, and
  its own read-only guarantee comes from the pack's `cli` block's allow-list instead of `K8sClient`.
- **`runwhen.resourceSync`** -- a JSON string: `{"apiBaseUrl", "token", "workspace", "expiresAt"}`.
  The token is a short-lived JWT, minted specifically for this one run, scoped to
  `resources:sync`, and bound to both the workspace and the capability run that requested it. The
  platform accepts this token type only on the handful of routes that declare that scope (pack
  registration and every sync-protocol route from §3, plus resource-path minting); every other
  route rejects it outright. The token also stops working once the run that requested it reaches a
  terminal state, whether or not `expiresAt` has passed yet.

Both credentials are minted fresh per run/lease; neither is ever handed back to the capability in
a form it could read again later, and nothing about either credential is cached across runs.

## 5. The capability's tasks

A capability ships a manifest (the RunWhen capability manifest format) declaring an execution
profile, which subjects it applies to, the credentials it needs (§4), a `setup` task that runs
once per request before anything else, and its own task list -- each task with typed inputs and
outputs. `k8s-discovery` declares three:

- **`connect`** (setup) -- inputs `{context?}`; runs once per request. Materializes the
  `kubeconfig` credential into an API client, confirms the cluster is actually reachable, and
  reads two small facts every following task can reference (`serverVersion`, the cluster's
  `clusterUid`). If the cluster can't be reached, the whole request fails here, before `discover`
  ever starts. `context` is the same input `discover` accepts (below) -- it must be given here
  too, so this precheck actually covers the context the request itself uses rather than always
  checking the kubeconfig's default current-context.
- **`discover`** -- inputs `{clusterName, namespaces?, excludeNamespaces?, configMapValues?,
  overlay?, context?}`; output `summary` (kind `rw.discovery_summary.v1`):
  `{syncId, packDigest, counts, partitions, durationMs, serverVersion, clusterUid,
  rollupSourcesUnavailable}`. No bulk data ever rides this output -- every discovered resource goes
  straight to the platform through the sync protocol (§3); this result is only the run's own
  accounting. It registers the type/facet/rule pack (§2), opens a sync (§3), pushes items with
  every ancestor pushed before its children, and commits with one partition per `(type,
  parentPath)` it actually attempted to enumerate. A namespace `namespaces`/`excludeNamespaces`
  leaves out of scope gets `excluded` partitions instead -- for the namespace itself and for every
  namespaced type -- never `complete`, so §3's sweep leaves it, and everything under it, alone;
  narrowing scope this way is non-destructive. Any failure once the sync is open aborts it,
  rather than leaving it to expire on its own lease. `rollupSourcesUnavailable` maps a namespace
  name (or `""`, the cluster scope) to which of the ephemeral, rollup-only source collections
  (pods, ReplicaSets, EndpointSlices, Events) plus Jobs and Nodes (both stored resources in their
  own right, but also read once more here to compute a rollup) came back forbidden or failed this
  run; a rollup facet whose sources are listed there was omitted from every item it would have
  applied to, rather than pushed with a false empty or zero count (the platform keeps the last
  value it had and ages it into `stale` by the facet's own TTL instead).
- **`cli`** -- inputs `{clusterName, argv, maxBytes?, timeoutSeconds?}`; output `result` (kind
  `rw.cli_result.v1`): `{argv, exitCode, stdout, stderr, truncated, stdoutBytes, durationMs,
  rejected?}`. Declared `readOnly: true` and `invocation: [sync]` in the manifest: papi calls it
  synchronously, and it never writes to the platform's inventory. It is this capability's one
  exception to "never shells out" -- see §7 for its full validation and execution contract.
  `inspect` (a narrower, sanitized `get`/`describe` over the Kubernetes API, no shell) has been
  retired in `cli`'s favour: `cli` is now the agent's one read path into a cluster.

`discover`'s bulk push is the only thing that goes through the sanitizer -- see this repo's
README, "Sanitization policy" section, for the full policy (what is dropped, what is masked, and
why). `cli`'s read-only guarantee is a different mechanism entirely: the pack's `cli` block's
verb/flag/sensitive-type allow-list (§7), not this sanitizer.

`context`, on `discover` (the only task that still accepts it -- `cli` has no `context` input of
its own and always runs against the kubeconfig's current-context, §7), names one of the
`kubeconfig` credential's own contexts to build the API client from, instead of its
current-context -- the credential itself is unchanged; `context` only selects which of its
contexts this particular run addresses. Checked against the kubeconfig's own `contexts:` list
before the task does anything else; a context the kubeconfig does not have fails the task
immediately, naming it (`rwdiscovery/credentials.py`'s `KubeconfigError`), never a silent
fall-back to current-context.

## 6. Capability image releases

`k8s-discovery` follows the same capability-image release model as `rw-checks-codecollection`
(that repo's PR introducing it, and `codecollection-registry`'s catalog reader that consumes it,
are the reference implementations this section mirrors):

- **No `image:` key in the manifest.** An image cannot know its own digest at the time it is
  built; the registry and catalog own that mapping, not this repo's checked-in `manifest.yaml`.
- **The manifest rides the image itself.** Every pushed image carries the base64 (no line breaks)
  of its own `manifest.yaml`, verbatim, as the OCI label `com.runwhen.capability.manifest.v1`.
  `scripts/manifest_label.py` computes it at build time; `Dockerfile.k8s-discovery` bakes it in via
  a build arg. The codecollection catalog reads this label straight off the pushed image's config
  blob -- never a separate build artifact, and never a platform release -- to learn the
  capability's id, version, and full manifest.
- **The output schemas ride the image too.** A task output's `schema:` value (e.g.
  `./schemas/cli_result.v1.json`) only names the JSON Schema file, relative to `manifest.yaml`;
  the file itself does not otherwise leave this repo. A second OCI label,
  `com.runwhen.capability.schemas.v1`, carries the base64 of one compact JSON object mapping every
  schema file in the capability's `schemas/` directory (not only the ones the current manifest
  references -- see "Schema files are versioned and immutable" below), keyed by its normalized
  path, to its parsed contents -- computed by the same `scripts/manifest_label.py`, which fails
  the build if a referenced schema is missing, invalid JSON, or not a JSON object. This lets the
  codecollection catalog validate a capability's outputs against the exact schema version that
  shipped with the image, without a bundled copy of its own that could drift.
- **Schema files are versioned and immutable.** Every file under `schemas/` is named
  `<name>.v<N>.json` (`N` >= 1); anything else fails a naming check. Once committed, a schema file
  never changes and is never deleted -- a model's shape change adds `<name>.v<N+1>.json` instead,
  and the manifest's `schema:` ref moves to it; the old file (and every already-published run's
  result that names it) keeps resolving. `scripts/check_schema_immutability.py` enforces both
  rules in CI on every push and pull request, comparing the working tree's versioned schema files
  against the base branch/commit as canonical JSON (so a whitespace-only reformat is not a
  change). Because the image label carries every version, not only the referenced one, this is
  purely additive: nothing a consumer already resolved stops working when a new version ships. A
  schema change that platform consumers must handle differently should also bump the output's
  `kind` (e.g. `rw.discovery_summary.v1` -> `rw.discovery_summary.v2`) -- a convention for
  capability authors, not something enforced mechanically.
- **Semver tags are releases.** Pushing a tag matching `v<major>.<minor>.<patch>` publishes the
  canonical, immutable release image under that tag alone -- no `-<sha7>` suffix (unlike a branch
  build, where the suffix is what makes an otherwise-moving tag immutable), no `latest`, no branch
  alias. The catalog's `stable` channel resolves to the highest semver tag published this way.

## 7. Platform CLI (`cli` task)

The one place this capability shells out to anything: a single, allow-listed, read-only `kubectl`
command, run synchronously and returned in the same response -- no `capability_runs` row, nothing
stored. papi's `POST /api/v4/workspaces/{workspace}/platform-cli/{name}:run` resolves the pack
whose `cli.name` matches, validates the command, and dispatches it to this capability's `cli` task
over the stateless-sync runner path; only a structured audit log line and metrics survive the call
on papi's side.

**The pack's `cli` block** (`packs/kubernetes/pack.yaml`, alongside `access`) is what papi validates
a request against, and what this capability loads (`packbuild.load_pack_yaml()["cli"]`,
`rwdiscovery/cli.py`) to re-validate and execute one. It is an **allow-list**:

```
cli  {name, capability, task,
      flags: {<long-name>: {short?: <one letter>, value?: bool, pseudo?: bool}},
      verbs: {<verb>: {flags: [<long-name>], outputs?: [str]}},
      sensitiveTypes: [str], sensitiveOutputs: [str],
      output: {defaultBytes, maxBytes, timeoutSeconds, maxTimeoutSeconds}}
```

`name` is the agent-facing tool/endpoint name (`^[a-z][a-z0-9-]{1,31}$`); `capability`/`task` name
which capability and task actually run it (`k8s-discovery`/`cli` here). `flags` declares every flag
the CLI may ever take, by long name (`[a-z][a-z0-9-]*`): `short` is its one-letter form (unique across
flags), `value` says it takes a value (otherwise it is a boolean), and `pseudo` marks a flag this
capability handles itself and never passes to kubectl (`grep`). A flag that isn't declared -- every
credential, context or server override, `-f`/`--filename`, `--raw`, `--watch`/`--follow`, `-v` and the
profiling flags among them -- can never be used at all. `verbs` maps each allowed verb (one or two
words: `get`, `logs`, `auth can-i`, `rollout history`, ...) to the declared flags it allows and, for a
verb that allows `output`, the `-o` values it allows (`outputs`; an entry ending in `=*`, like
`jsonpath=*`, allows any value with that prefix). `sensitiveTypes` (`secret`, `secrets`) restricts
every verb on those types to the default table view or one of `sensitiveOutputs` (`name`, `wide`) --
never a full object dump. `output` bounds how much a command can ask for: `maxBytes`/
`maxTimeoutSeconds` are hard ceilings; `defaultBytes`/`timeoutSeconds` apply when a request doesn't
specify one.

**Validation** (identical rules in papi and here, held to the same shared vector file,
`tests/cli_vectors.json` -- papi's own copy exists for early, helpful errors; this capability's is
authoritative, since it is the one that actually execs anything). The command is parsed the way
kubectl's own flag parser (pflag) parses it, and the first violated rule is the rejection:

1. Split the command with `shlex.split(command, posix=True)` (a split failure is `unparsable`); the
   request's `argv` arrives already split and skips this. Drop a leading `kubectl` token. Nothing
   left is `empty`.
2. A token that is exactly one of `| || & && ; > >> < <<`, starts with `$(` or a backtick, or ends
   with `;` is `no-shell`: one kubectl invocation per call, never a shell, and `--grep` is the tool
   for filtering output. A `|` inside a flag value (`--grep=ERROR|FATAL`) is fine.
3. The verb is the first two tokens when that pair is a declared verb, otherwise the first token;
   anything else is `verb-not-allowed`.
4. The remaining tokens, left to right: `--` is `flag-not-allowed`. `--name[=v]` must name a declared
   flag the verb allows (`flag-not-allowed` otherwise, and the hint lists the verb's flags); a value
   flag takes `v` or, without `=`, the next token (none is `missing-value`); a boolean's `=v` must be
   `true` or `false` (`bad-value`). A short cluster (`-` then a letter: `-A`, `-Al`, `-oyaml`,
   `-o=json`) is read one letter at a time: each must be the `short` of a flag the verb allows; a
   boolean continues the cluster, a value flag takes the rest of the token (a leading `=` stripped)
   or, when that is empty, the next token, and ends it. Every other token is a positional argument.
   A flag may repeat, except `output` and `grep` (`flag-not-allowed`).
5. The `output` value must be one of the verb's `outputs` (or match a `=*` prefix entry):
   `output-not-allowed` otherwise.
6. The first positional, split on `,`, each part cut at `/`, lower-cased and cut at the first `.`
   (`Secret`, `secret/s1`, `secrets.v1`, `secret,pods` all resolve to `secret`/`secrets`), is checked
   against `sensitiveTypes`: a match with `output` set to anything outside `sensitiveOutputs` is
   `sensitive-type`.
7. `grep` is a pseudo-flag: removed from the argv, and its value must compile as a Python regex
   (`invalid-grep` otherwise). It is applied as a case-insensitive line filter to captured stdout.
8. For `logs`: `--tail=200` is added when none of `tail`/`since`/`since-time` was given;
   `--limit-bytes` must be a positive integer (`bad-value`; kubectl reads 0 as no limit), is clamped down to `4 × the effective maxBytes`,
   and is added at that value when not given.
9. The **normalised argv** is the verb's tokens, the positionals in order, then every flag in order of
   appearance as `--name=value` (value flags), `--name` (booleans given without `=`) or
   `--name=true|false` (booleans given with `=`), then any added defaults. This is the only argv ever
   exec'd -- never the tokens as given.

A rejection is `{reason, hint}` -- never raised, never partially executed. The reasons are `empty`,
`unparsable`, `no-shell`, `verb-not-allowed`, `flag-not-allowed`, `missing-value`, `bad-value`,
`output-not-allowed`, `sensitive-type` and `invalid-grep`; the hint says what to change.

**Execution** (`rwdiscovery/cli.py`'s `run_cli`, mirroring how `discover` receives its credential --
`tasks.py`): the `kubeconfig` credential is written to a 0600 file inside the request's own scope
directory (the same convention `credentials.py` uses for the Python client), and `kubectl` is run as
a real subprocess -- no shell -- as `kubectl --kubeconfig <file> --request-timeout=<t>s <argv>`,
`argv` being the normalised argv from above. The child's environment is scrubbed to exactly `PATH`/`HOME`/`KUBECONFIG`; nothing else from the pod's own environment reaches
it. A wall-clock timeout of `t + 2` seconds kills the process outright (`t` is the request's
`timeoutSeconds`, clamped to the pack's `output.timeoutSeconds`/`maxTimeoutSeconds`). stdout is read
incrementally, `--grep`'s filter applied to each line *before* it counts against `maxBytes` (a
dropped line costs nothing; the stream is still drained past the cap so the process isn't left
blocked on a full pipe), so the response is genuinely the first `maxBytes` of *matching* output, not
a somewhat-larger raw capture. stderr is capped independently, at a fixed 4 KB, no filtering. The
kubeconfig file is removed once the command has finished, success or not.

**`rw.cli_result.v1`** (the `cli` task's only output): `{argv: [str], exitCode: int, stdout: str,
stderr: str, truncated: bool, stdoutBytes: int, durationMs: int, rejected: {reason, hint} | null}`.
`rejected` is set, and `exitCode` is `-1`, exactly when validation failed -- `subprocess` is never
invoked in that case. `argv` is the normalised argv actually run (for a rejected request, the argv
as received); it never carries `--kubeconfig`/`--request-timeout`, which are the executor's own
addition, not part of the validated command.
