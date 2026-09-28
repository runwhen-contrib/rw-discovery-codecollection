"""`enc()`: a local mirror of one rule from papi's path grammar
(platform-contract §1) -- its name-encoding step.

papi is the sole minter of `resources.path` -- `discover` never sends a path,
only a typed chain (`chain.py`), and papi mints it at sync time. `discover.py`
still needs to hand-build two path-shaped strings of its own, `scopePath` and
`parentPath` (`scope_path_for`, `_partition_parent_path`) -- strings this
module constructs itself, unlike an item's `identity.chain`, which papi
mints -- so they must already be in papi's canonical, percent-encoded form,
or a cluster name containing `:`/`/` (an EKS ARN, for instance) would mint a
different path than the one this run's own items resolve under. `enc()` is
that one encoding rule, mirrored locally so those two call sites don't need
a round trip to papi for a value they can compute themselves. If papi's own
encoding rule ever changes, this function (and `tests/test_path.py`) must
change with it -- it is a mirror, not an independent authority.

    enc(name)  = apply name_case (lower|preserve), Unicode NFC, then
                 percent-encode (uppercase hex) ':' '/' '%' '#' '?',
                 whitespace and control chars; everything else passes through
"""

from __future__ import annotations

import unicodedata

_ENCODE_CHARS = frozenset(":/%#?")


def _needs_encoding(ch: str) -> bool:
    return ch in _ENCODE_CHARS or ch.isspace() or unicodedata.category(ch) == "Cc"


def enc(name: str, name_case: str = "preserve") -> str:
    if name_case == "lower":
        name = name.lower()
    name = unicodedata.normalize("NFC", name)
    out = []
    for ch in name:
        if _needs_encoding(ch):
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
        else:
            out.append(ch)
    return "".join(out)
