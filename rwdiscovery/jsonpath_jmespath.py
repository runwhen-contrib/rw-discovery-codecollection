"""JSONPath (as used by a CRD's `additionalPrinterColumns`) -> JMESPath,
for the generated `k8sSummary` facet: a CRD's per-version printer columns
become that facet's `expressionByType` entry for its type (platform-contract §2).

A CRD's printer-column JSONPath is a small, well-known subset --
`kubectl get` never lets an operator author anything richer. This
converts:

  - a leading `.` (JSONPath's root-relative form) -- dropped, since
    JMESPath expressions here are always relative to the object's
    `status`/`spec` document root, same as the printer column itself;
  - dotted segments and `[n]` indices -- unchanged, both languages agree;
  - `[?(@.field OP value)]` filter expressions -- rewritten to JMESPath's
    `[?field OP value]` (JMESPath's `@` means the *current* node inside a
    filter, so a field reference never carries it).

Multi-condition filters (`&&`/`||`) are handled the same way, since the
`@.` stripping is applied to the whole filter body. Anything else a CRD
author might in principle write in `additionalPrinterColumns` (functions,
`..` recursive descent) is out of scope -- `kubectl` itself never emits
that shape either.
"""

from __future__ import annotations

import re

_FILTER_RE = re.compile(r"\[\?\((?P<body>.+?)\)\]")
_AT_DOT_RE = re.compile(r"@\.")
# JSONPath filters quote string literals with double quotes (kubectl's own
# printer-column examples do this); JMESPath's raw string literal syntax
# uses single quotes instead -- a double-quoted token in JMESPath is a
# quoted *identifier*, not a string, so leaving the quoting as-is would
# compile but silently never match anything (see test_jsonpath_jmespath.py).
_DOUBLE_QUOTED_RE = re.compile(r'"([^"]*)"')


def jsonpath_to_jmespath(json_path: str) -> str:
    path = json_path.strip()
    if path.startswith("."):
        path = path[1:]
    if not path:
        return "@"

    def _convert_filter(match: re.Match) -> str:
        body = _AT_DOT_RE.sub("", match.group("body"))
        body = _DOUBLE_QUOTED_RE.sub(r"'\1'", body)
        return f"[?{body}]"

    return _FILTER_RE.sub(_convert_filter, path)
