# rw-discovery-codecollection

RunWhen CodeCollection for infrastructure discovery -- a **capability image**, built on the
`runwhen_capability` SDK and its `rwtask` task host, not a Robot codebundle collection.

## What this is

This repository ships the **`k8s-discovery`** capability: it enumerates a Kubernetes cluster's
resources via the API server, sanitizes every object at the source, and pushes them to papi's
resource inventory over the resource-sync protocol. It runs read-only against the cluster
(`discover` also writes to papi; `inspect` is entirely read-only) and never shells out to
`kubectl` or anything else -- every read goes through the Kubernetes API directly.

- **`rwdiscovery/`** -- the Python core: API enumeration and pagination, sanitization, the
  Kubernetes identity/chain rules, rollups over ephemeral objects, the pack builder, and the sync
  protocol client.
- **`capabilities/k8s-discovery/`** -- the capability: a manifest (`manifest.yaml`), its tasks
  (`tasks.py`: `connect` setup, `discover` and `inspect` tasks), and the JSON Schema exported from
  `rwdiscovery`'s models (`schemas/`).
- **`packs/kubernetes/pack.yaml`** -- the Kubernetes pack: facet definitions and dependency rules
  registered with papi at the start of every `discover` run. Builtin type specs come from
  `rwdiscovery/chain.py`, not this file -- see its header comment.

Code comments cite `platform-contract §N`, short for [`docs/platform-contract.md`](docs/platform-contract.md)
-- this repo's own description of the papi interface (resource identity, packs, the sync protocol,
credentials) that this package implements. This README is the public entry point and stands on its
own; the platform-contract doc is there for anyone extending or reviewing the code who needs the
interface spelled out precisely.

## What `discover` does

1. Registers the Kubernetes pack with papi. The registration body has a **static** part (type
   specs, facet definitions, dependency rules that are identical for every cluster) -- idempotent
   by digest, a no-op once nothing has changed -- and an **additive** part (`additiveTypes`,
   `additiveFacetDefinitions`) carrying whatever *this* cluster's own discovery found: its
   CustomResourceDefinitions, aggregated APIs, and their `k8sSummary` facets. Additive entries are
   upserted and never removed by another cluster's registration; one conflicting with an existing
   type is skipped (logged, not fatal) and any item of that type is later rejected when pushed,
   failing only its own partition.
2. Opens a full resource sync for this cluster's scope.
3. Enumerates every listable API resource (`/api` and `/apis` preferred versions -- the same set
   `kubectl api-resources --verbs=list` shows, so CRDs are included automatically), pages through
   each one (`limit=500` + `continue`, cluster-wide where RBAC allows it, otherwise per
   namespace), sanitizes every object, and pushes it in batches (cluster, then namespaces, then
   everything else).
4. Ephemeral types (pods, ReplicaSets, EndpointSlices, events, leases, ...) are never pushed as
   resources -- but pods, ReplicaSets, EndpointSlices and events are still read, to compute
   **rollups** (pod counts/restarts, service endpoint readiness, CronJob's recent runs, cluster
   version/distribution) attached to the resources they belong to. A standalone Job is stored; a
   Job owned by a CronJob is not, since a CronJob recreates it on every schedule. A `403`/error
   reading one of these rollup sources (pods, ReplicaSets, EndpointSlices, Jobs, events, Nodes) is
   never treated as "zero of that" -- a rollup facet whose sources aren't all readable is omitted
   from every item it would apply to, rather than pushed with a false empty/zero value; the summary
   (below) reports which sources were unavailable, per namespace.
5. Commits the sync with one partition per `(type, parentPath)` listed, so papi can safely sweep
   only what was actually observed as complete -- a `403` on a type/namespace is reported
   `forbidden`, never silently treated as "zero of that type"; a rejected item (an unknown type, a
   missing parent) fails its whole `(type, parentPath)` partition the same way. When an explicit
   `namespaces` input is given and listing namespaces cluster-wide is itself forbidden, each one is
   `GET` individually instead -- a minimal-privilege ServiceAccount is commonly granted `get` on
   specific namespaces but not a cluster-wide `list`. A namespace that even that GET can't reach
   still gets pushed as a stub (identity only, a marker annotation) so its children have a parent;
   the namespace partition is reported `forbidden` either way.
6. Returns a summary (`rw.discovery_summary.v1`): sync id, pack digest, counts, partition status
   breakdown, duration, server version, cluster UID, and which rollup sources (if any) were
   unavailable, keyed by namespace (`""` for the cluster scope). **No bulk data returns through
   the capability's own result** -- everything else goes straight to papi through the sync API.

Any failure after the sync is opened aborts it, rather than leaving it to expire on its own lease.

### Inputs (`discover`)

| input | type | required | notes |
|---|---|---|---|
| `clusterName` | string | yes | Becomes the cluster resource's name -- must match RunWhen Local's `cluster.name` so the later SLX<->resource join is string equality. |
| `namespaces` | string[] | no | Explicit in-scope namespace list. When omitted, scope is every namespace minus `excludeNamespaces`. |
| `excludeNamespaces` | string[] | no | Ignored if `namespaces` is set. |
| `configMapValues` | `"store"` \| `"keysOnly"` | no (default `store`) | `keysOnly` drops ConfigMap values, keeping only per-key size/hash -- for a hosted, multi-tenant install. |
| `overlay` | object | no | `{"redactions": ["dotted.path", ...]}` -- an early, minimal hook for platform-level extra redactions; a fuller, workspace-configured version of this is expected to land later. |

### What `inspect` does

`get` or `describe` exactly one object, read-only, no shell:

- resolves the object's real API plural via discovery (targeted to one group/version when
  `apiVersion` is given, a full discovery sweep otherwise);
- fetches it, and sanitizes it through the **same** `rwdiscovery.sanitize` module `discover` uses
  -- there is no side door for a Secret's data to leak through this path;
- computes its `path` with the same chain-building rules `discover` uses (a local, read-only
  mirror of papi's path grammar -- see `rwdiscovery/path.py`'s docstring for why papi's own
  minting isn't called here);
- in `describe` mode, also fetches events involving the object and renders a plain-text summary
  (`rwdiscovery/describe_render.py`) -- built from the sanitized document, never a `kubectl
  describe` shell-out, since this capability has no shell access to begin with.

### Inputs (`inspect`)

| input | type | required |
|---|---|---|
| `clusterName` | string | yes |
| `kind` | string | yes |
| `name` | string | yes |
| `namespace` | string | no (omit for a cluster-scoped kind) |
| `apiVersion` | string | no (`"group/version"` or `"v1"` for core; resolved via discovery if omitted) |
| `mode` | `"get"` \| `"describe"` | yes |

## Credentials

Declared in `capabilities/k8s-discovery/manifest.yaml`'s `needs.credentials`, resolved by papi at
lease time (platform-contract §4) -- the task never knows a secret name, only a kind:

| name | kind | access | shape |
|---|---|---|---|
| `kubeconfig` | `k8s.kubeconfig` | read | the kubeconfig YAML, as a string |
| `resourceSync` | `runwhen.resourceSync` | write | JSON: `{"apiBaseUrl", "token", "workspace", "expiresAt"}` -- a short-lived, lease-scoped token valid only on the resource-pack/resource-sync routes |

The kubeconfig is written to a temp file **inside the request's own scope directory**
(`rwdiscovery/credentials.py`), never to `~/.kube/config` or a `KUBECONFIG` env var -- both would
race across `inspect`'s concurrent requests in one pod. Even the Kubernetes client library's own
incidental temp files (materialised from inline base64 CA/cert/key data) are redirected into that
same scope directory, so the whole credential footprint is wiped when the task host cleans up the
request, and none of it lingers in the pod's shared `/tmp`. The raw kubeconfig file itself is
deleted the moment it has been loaded.

**Not supported in v1:** a kubeconfig whose auth depends on an **exec credential plugin**
(`gke-gcloud-auth-plugin`, `aws eks get-token`, `kubelogin`, ...) -- the image ships no shell tools
and none of those plugin binaries (`Dockerfile.k8s-discovery`'s final stage has no `git`, no cloud
CLIs, nothing to exec), so `client.Configuration()` fails to invoke one and the credential is
rejected as a `KubeconfigError`, the same class covering any other malformed/unsupported
kubeconfig -- never a silent misbehavior. A **static** kubeconfig -- a bearer token or a
client-cert/key pair inline in the file, no `exec:` block -- works, which covers the common
in-cluster case: a ServiceAccount's own kubeconfig (token or projected cert) that RunWhen Local or
an operator generates for this capability to use.

## Sanitization policy

Nothing leaves the cluster that a read-only platform user shouldn't see. This runs identically for
`discover`'s bulk pushes and `inspect`'s single-object reads (`rwdiscovery/sanitize.py`):

- `metadata.managedFields` is dropped from every object.
- The `kubectl.kubernetes.io/last-applied-configuration` annotation is dropped -- for a Secret it
  would otherwise carry the data.
- **Secret:** only metadata, `type`, and the **key names** survive (`secretKeys`). `data` and
  `stringData` are removed entirely -- never partially masked, never present. Annotation *values*
  are replaced with a marker unless the key has one of a short allowlist of safe-by-convention
  prefixes (`kubernetes.io/`, `cert-manager.io/`, `meta.helm.sh/`, `app.kubernetes.io/`,
  `helm.sh/`) -- keys always survive. This closes a real side door: kapp's `kapp.k14s.io/original`
  and similar "last full manifest" conventions can carry the *whole* Secret, base64 `data` included,
  as one annotation value, and a short base64 value embedded in a large JSON blob is far below the
  generic credential masker's high-entropy length floor.
- **ConfigMap:** values are stored in full by default (`configMapValues: store`) -- they're needed
  for configuration questions and for dependency rules (hosts, URLs and service names inside
  config are where most real dependencies live). `binaryData` is always reduced to size (+ hash,
  see below). Every key also gets an entry in `dataHashes`, computed before masking, so "this
  value changed" and "these ConfigMaps share a value" survive display-time masking -- **for values
  that weren't masked**: a value masked by its key name or a credential shape found inside it
  stores only its `size`, never a `sha256` of what it actually held (a hash is still a commitment
  to the exact value). `configMapValues: keysOnly` drops the values entirely (for a hosted,
  multi-tenant install) and is stricter still: every hash is `size` only, masked or not.
- **Credential masking keeps structure**, for ConfigMap values and container `env[].value` alike:
  - lines shaped like `key=value`, `key: value`, `key = value` or `"key": "value"` inside an
    otherwise-opaque string (a ConfigMap value that is itself a small `.env`/properties/JSON-ish
    blob) have their value masked when the key's last dotted/underscored segment names a
    credential -- catching an ordinary, non-high-entropy password (`DB_PASSWORD=hunter2`) that no
    other rule below would catch, while leaving every other line, including a URL or host, alone;
  - a DSN/URL's userinfo password is masked, keeping scheme, host, port and database
    (`postgres://app:****@orders-db.svc:5432/orders`);
  - PEM blocks, JWTs, and recognizable cloud access-key formats (AWS access key IDs, GitHub
    tokens, Slack tokens) are masked wherever they appear in a string;
  - a generic high-entropy-token heuristic catches other long, mixed-case/punctuated secrets --
    deliberately excluding strings of only lowercase letters, digits and `-` (Kubernetes names,
    UIDs, git SHAs, image digests), which are the references dependency rules join on;
  - a **narrow** set of key/variable names (`password`, `passwd`, `secret`, `token`, `apikey`,
    `api_key`, `private_key`, `credentials`, matched against the key with separators stripped, so
    `DB_PASSWORD` and `API_TOKEN` match) triggers whole-value masking regardless of content.
    Broad words like `key`, `auth`, `conn`, `dsn` are deliberately **not** in this list -- they
    name hosts and connection strings far more often than bare secrets. Keys that name an object
    (`secretName`, `*Ref`, `*Namespace`) are exempt: their value is a reference. The same rule
    applies to the `value` of any `{name, value}` pair (Argo CD helm parameters, Tekton params).
  - `env[].valueFrom` is left completely untouched -- it's a reference, not a value, and
    references are what dependency rules are built from.
- `status` is split off from the document but goes through the same masking and truncation;
  so do Secret and ConfigMap metadata, and `inspect`'s events.
- Every other string over 16 KB (annotations, args, arbitrary CRD fields) is truncated with a
  `***TRUNCATED:size=N:sha256=...***` marker. ConfigMap `data` values are the one exception --
  never truncated, since Kubernetes already caps a whole object at 1 MiB.

This is the same code path for both tasks, so there is no way to reach a Secret's data, or an
untruncated/unmasked credential, through `inspect`'s `get`/`describe` that `discover`'s bulk push
doesn't already enforce.

## The Kubernetes pack

`packs/kubernetes/pack.yaml` carries the platform's **static** facet definitions and dependency
rules (platform-contract §2) -- the part that is identical for every cluster this pack is registered
against -- **not** its type specs, which are generated live from `rwdiscovery/chain.py`'s builtin
table (`rwdiscovery/packbuild.py`), so there is exactly one place that knows the Kubernetes builtin
type table. `tests/test_pack_yaml.py` compiles every JMESPath expression and checks every
strategy/edgeType against the closed vocabulary platform-contract §2 defines.

Whatever a given cluster's own discovery turns up -- CustomResourceDefinitions, aggregated APIs
(`apiregistration.k8s.io/APIService`, metrics adapters, ...), and any other listable resource not
already covered -- is registered separately, as the pack PUT's **additive** part: `additiveTypes`
for the type specs, `additiveFacetDefinitions` for the `k8sSummary` facet's per-CRD
`expressionByType` entries (built from each CRD's `additionalPrinterColumns`). The digest that
makes registration idempotent covers only the static part, so two clusters with different CRDs
installed never fight over the pack's digest; papi upserts additive entries independently and never
removes one because a different cluster's registration didn't mention it. An additive type that
conflicts with an existing registration (a different parent or plural) comes back in the response's
`skipped` list -- `rwdiscovery/sync.py` logs it and moves on rather than failing the whole
registration; any item of that type is still rejected once pushed, failing only its own partition
(`rwdiscovery/sync.py`'s existing rejected-item handling).

## Local development

A capability author needs no cluster to develop against the SDK. `rwtask run` (from
`runwhen_capability`, this repo's SDK dependency) is the reference implementation: the same code
path the task host runs in production, against the local filesystem.

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Exercising `inspect` against a real cluster, read-only

`inspect` needs only the `kubeconfig` credential (it never calls `ctx.credential("resourceSync")`),
so it can be smoke-tested against any cluster your own kubeconfig can already reach, without a papi
endpoint:

```
cat > /tmp/credentials.json <<JSON
{"kubeconfig": "$(cat ~/.kube/config | sed 's/"/\\"/g')"}
JSON

cat > /tmp/request.json <<'JSON'
{
  "version": 1,
  "setup": {"task": "connect", "inputs": {}},
  "tasks": [
    {"task": "inspect", "inputs": {
      "clusterName": "dev", "kind": "Namespace", "name": "kube-system", "mode": "get"
    }}
  ]
}
JSON

rwtask run capabilities/k8s-discovery --request /tmp/request.json --credentials /tmp/credentials.json
```

Prints the `ResultEnvelope` (setup + task status/outputs/error) as JSON. This is read-only: no
kubeconfig content, and nothing read from the cluster, should ever be committed to this repo --
only hand-written synthetic fixtures belong in `tests/fixtures/` and `packs/kubernetes/vectors/`.

`discover` additionally needs the `resourceSync` credential (a real papi endpoint + lease-scoped
token) to do anything beyond registering the pack, so exercising it end to end locally means
pointing it at a real (likely local/dev) papi. The fake-cluster, fake-papi end-to-end test
(`tests/test_discover_e2e.py`) is the fast, offline way to exercise the whole `discover` flow --
run it as part of `make test`.

### Running the image directly

```
docker build -f Dockerfile.k8s-discovery -t k8s-discovery:dev .
docker run --rm k8s-discovery:dev rwtask --help
```

In production the image is never driven directly: `rwtask serve --relay <url> --pool <poolId>`
long-polls the runner as a warm executor, executing one request (`connect` + `discover` or
`inspect`) at a time and posting the result back. The image's `CMD` already bakes in its own
`--capability-dir` so it never has to guess which capability it is serving.

## Tests

```
make test        # python -m pytest -q
make lint         # ruff check .
make fmt-check    # ruff format --check .
make schemas      # regenerate capabilities/k8s-discovery/schemas/*.json from rwdiscovery.models
make vectors      # pack.yaml JMESPath validation + chain vectors, in isolation
```

All tests are offline, against hand-written synthetic fixtures (`acme-*` names) and an in-process
fake Kubernetes API (`tests/fakes.py`) -- never a real cluster. `tests/test_discover_e2e.py` is the
broadest one: a small synthetic cluster (Deployment/ReplicaSet/Pods, Service/EndpointSlice,
ConfigMap/Secret, CronJob/Job) discovered against a fake papi (`responses`), asserting push order,
batch sequencing, sanitization, rollups, and commit partitions end to end.

## SDK dependency

This repo depends on `runwhen_capability` from `rw-checks-codecollection`, pinned by commit SHA
(`pyproject.toml`) -- the VCS equivalent of a hash pin (pip's `--require-hashes` mode does not
support VCS requirements at all, so this one dependency installs in its own, non-hash-checked step
in `Dockerfile.k8s-discovery`; see that file's header comment). No packaging or SDK changes were
needed upstream: `rw-checks-codecollection`'s own `pyproject.toml` lives at its repo root and
packages only `sdk/`, so a plain git dependency resolves to the `runwhen_capability` package alone.
