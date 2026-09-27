"""Drain-lite -- a small, deterministic clone of Drain's fixed-depth,
similarity-threshold clustering (He et al., "Drain: An Online Log Parsing
Approach with Fixed Depth Tree"), just the slice platform-contract
log-patterns-v0 §7.1 needs: turn already-masked, single-line messages into
token templates, with no persistence and no third-party dependency (drain3
was tried and seen collapsing distinct exception classes -- `PAPIError`,
`HTTPStatusError`, `PAPINetworkError` -- into one template; the guard below
exists to stop exactly that).

The same algorithm runs at the edge (`logsample.build_groups`, one instance
per container per scan) and on the platform (the rules parser, one instance
per `(resource_path, container)`); neither side persists a `DrainLite`
across calls -- each call starts from nothing and clusters only the
messages it was given, in arrival order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# A position where either side's token looks like an exception class or
# error-style word must match exactly -- otherwise two lines that are
# alike everywhere else could still collapse two different exception
# types into one `<*>` (§7.1).
_EXCEPTION_TOKEN_RE = re.compile(r"(?i)^[\w.$]*(?:exception|error|errno|fault)\w*:?$")

_SIMILARITY_THRESHOLD = 0.5  # stricter than Drain3's 0.4 default (§7.1)
_WILDCARD = "<*>"

_BucketKey = tuple[int, str | None, str | None]


@dataclass
class Cluster:
    """One template this `DrainLite` has produced so far. `id` is a stable
    handle a caller can key an accumulator by across calls to `add` --
    `tokens`/`template` keep changing in place as later messages join."""

    id: int
    tokens: list[str]

    @property
    def template(self) -> str:
        return " ".join(self.tokens)


def _bucket_key(tokens: list[str]) -> _BucketKey:
    # The first two tokens are never wildcarded (Drain depth 4): bucketing
    # on `(token_count, token[0], token[1])` up front means every cluster a
    # message is ever compared against already agrees with it there, so
    # similarity only has to weigh the rest of the line.
    tok0 = tokens[0] if len(tokens) > 0 else None
    tok1 = tokens[1] if len(tokens) > 1 else None
    return (len(tokens), tok0, tok1)


def _position_equal(cluster_token: str, message_token: str) -> bool:
    # A position the cluster has already generalised counts as equal -- it
    # carries no more information to lose by matching it again (§7.1).
    return cluster_token == message_token or cluster_token == _WILDCARD


def _similarity(cluster_tokens: list[str], tokens: list[str]) -> float | None:
    """`equal positions / token_count`, or `None` if the exception-token
    guard forbids joining this cluster outright."""
    equal = 0
    for cluster_token, token in zip(cluster_tokens, tokens):
        if _position_equal(cluster_token, token):
            equal += 1
            continue
        if _EXCEPTION_TOKEN_RE.match(cluster_token) or _EXCEPTION_TOKEN_RE.match(token):
            return None
    return equal / len(tokens)


def _joined_tokens(cluster_tokens: list[str], tokens: list[str]) -> list[str]:
    return [ct if _position_equal(ct, t) else _WILDCARD for ct, t in zip(cluster_tokens, tokens)]


class DrainLite:
    """One scan's (or one `(resource_path, container)`'s) worth of
    clustering -- not thread-safe, not persisted; a fresh instance per
    call (platform-contract §7.2)."""

    def __init__(self) -> None:
        self._buckets: dict[_BucketKey, list[Cluster]] = {}
        self._next_id = 0

    def add(self, text: str) -> Cluster:
        """Adds one already-masked message in arrival order, returning the
        `Cluster` it joined (a new one if none fit)."""
        tokens = text.split()
        bucket = self._buckets.setdefault(_bucket_key(tokens), [])

        if len(tokens) < 4:
            # Fewer than 4 tokens: only ever joins an identical template --
            # Drain depth 4 has nothing left to bucket on past this point,
            # so there's no similarity band to fall back to.
            for cluster in bucket:
                if cluster.tokens == tokens:
                    return cluster
            return self._new_cluster(bucket, tokens)

        best: Cluster | None = None
        best_similarity = -1.0
        for cluster in bucket:
            similarity = _similarity(cluster.tokens, tokens)
            if similarity is not None and similarity > best_similarity:
                # Strict `>`, not `>=`: ties keep the earlier `best`, which
                # -- since `bucket` is in arrival order -- is the older
                # cluster (§7.1).
                best, best_similarity = cluster, similarity

        if best is not None and best_similarity >= _SIMILARITY_THRESHOLD:
            best.tokens = _joined_tokens(best.tokens, tokens)
            return best
        return self._new_cluster(bucket, tokens)

    def _new_cluster(self, bucket: list[Cluster], tokens: list[str]) -> Cluster:
        cluster = Cluster(id=self._next_id, tokens=list(tokens))
        self._next_id += 1
        bucket.append(cluster)
        return cluster
