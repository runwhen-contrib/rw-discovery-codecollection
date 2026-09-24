"""A local, read-only mirror of papi's path grammar (platform-contract §1).

papi is the sole minter of `resources.path` -- `discover` never sends a path,
only a typed chain (`chain.py`), and papi mints it at sync time. This module
exists only so the `inspect` task can show a human-readable path in its own
output, computed by the same chain-building rules `discover` uses, without an
extra round trip to papi for a value it can compute locally from the same
rules. If papi's grammar ever changes, this module (and
`tests/test_path_vectors.py`) must change with it -- it is a mirror, not an
independent authority.

    enc(name)  = apply name_case (lower|preserve), Unicode NFC, then
                 percent-encode (uppercase hex) ':' '/' '%' '#' '?',
                 whitespace and control chars; everything else passes through
    path       = platform "/" plural(t0) "/" enc(n0) "/" ... "/" plural(tN) "/" enc(nN)
"""

from __future__ import annotations

import unicodedata

from .chain import ChainItem, TypeSpec

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


def build_path(platform: str, chain: list[ChainItem], specs_by_type: dict[str, TypeSpec]) -> str:
    """`specs_by_type` maps each chain element's type name to its TypeSpec,
    for its `plural` and `name_case`."""
    segments = [platform]
    for item in chain:
        spec = specs_by_type[item.type]
        segments.append(spec.plural)
        segments.append(enc(item.name, spec.name_case))
    return "/".join(segments)
