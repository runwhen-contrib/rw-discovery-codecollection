#!/usr/bin/env python3
"""Enforces the "versioned, immutable schemas" rule
(docs/platform-contract.md) for every capability's schemas/ directory:

  1. Naming -- every file under capabilities/*/schemas/ must match
     `<name>.v<N>.json` (lowercase letters, digits, underscores; N >= 1).
     Anything else fails, so a stray README or an un-versioned filename in a
     schemas/ directory is caught here rather than shipped.
  2. Immutability -- a published schema file never changes and is never
     deleted once committed. This compares every versioned file that existed
     at `--base` (a git ref: the PR's target branch, or the previous commit
     on a push) against the working tree, as canonical JSON, and fails if
     any such file changed or disappeared. A shape change is a new file at
     the next version instead; the manifest moves its `schema:` ref to it.
     A file at `base` that does NOT match the versioned naming pattern is
     exempt -- this is what lets a versioning migration retire old,
     unversioned filenames without tripping the check on itself.

`--base` empty, an all-zero sha (git's placeholder for "no previous commit",
e.g. a branch's first push), or otherwise unresolvable -> both checks still
run naming, but immutability is skipped with a notice (there is nothing to
compare against).

Usage: python3 scripts/check_schema_immutability.py --base <git-ref>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Lowercase letters, digits, underscores, then ".v<N>.json" with N >= 1 and no leading zero.
VERSIONED_NAME_RE = re.compile(r"^[a-z0-9_]+\.v[1-9][0-9]*\.json$")


def _canonical_json(text: str) -> str:
    """sort_keys, no whitespace -- so a whitespace-only reformat of an unchanged schema never
    trips the immutability check."""
    return json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))


def check_naming(repo_root: Path = REPO_ROOT) -> list[str]:
    """One error message per file under capabilities/*/schemas/ that doesn't match
    VERSIONED_NAME_RE. Empty list means every file is named correctly."""
    errors = []
    for path in sorted(repo_root.glob("capabilities/*/schemas/*")):
        if not path.is_file():
            continue
        if not VERSIONED_NAME_RE.match(path.name):
            rel = path.relative_to(repo_root)
            errors.append(
                f"{rel}: schema files must be named '<name>.v<N>.json' (lowercase letters, "
                f"digits, underscores only), got {path.name!r}"
            )
    return errors


def _run_git(args: list[str], repo_root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo_root, capture_output=True, text=True)


def is_base_resolvable(base: str, repo_root: Path = REPO_ROOT) -> bool:
    """False for an empty string, an all-zero sha (git's placeholder for "no previous
    commit"), or a ref git itself can't resolve to a commit."""
    if not base or re.fullmatch(r"0+", base):
        return False
    result = _run_git(["rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"], repo_root)
    return result.returncode == 0


def check_immutability(base: str, repo_root: Path = REPO_ROOT) -> list[str]:
    """One error message per versioned schemas/ file that existed at `base` and either changed
    (as canonical JSON) or was deleted in the working tree. Empty list means every published
    schema at `base` is untouched (or `base` isn't resolvable -- nothing to compare)."""
    if not is_base_resolvable(base, repo_root):
        print(f"check_schema_immutability: base {base!r} is not resolvable, skipping the immutability check")
        return []

    errors = []
    ls_tree = _run_git(["ls-tree", "-r", "--name-only", base, "--", "capabilities"], repo_root)
    if ls_tree.returncode != 0:
        errors.append(f"could not list capabilities/ at {base!r}: {ls_tree.stderr.strip()}")
        return errors

    for rel_path in ls_tree.stdout.splitlines():
        if not rel_path:
            continue
        name = Path(rel_path).name
        if not VERSIONED_NAME_RE.match(name):
            continue  # unversioned at base -- exempt, lets a versioning migration retire it

        show = _run_git(["show", f"{base}:{rel_path}"], repo_root)
        if show.returncode != 0:
            errors.append(f"{rel_path}: could not read from {base!r}: {show.stderr.strip()}")
            continue
        base_text = show.stdout

        working_path = repo_root / rel_path
        if not working_path.is_file():
            next_version = re.sub(r"\.v[1-9][0-9]*\.json$", "", name)
            errors.append(
                f"{rel_path}: a published schema was deleted -- a published schema file never "
                f"changes or disappears; add {next_version}.v<N+1>.json instead"
            )
            continue

        working_text = working_path.read_text(encoding="utf-8")
        try:
            changed = _canonical_json(base_text) != _canonical_json(working_text)
        except json.JSONDecodeError as exc:
            errors.append(f"{rel_path}: not valid JSON at {base!r} or in the working tree: {exc}")
            continue
        if changed:
            next_version = re.sub(r"\.v[1-9][0-9]*\.json$", "", name)
            errors.append(
                f"{rel_path}: a published schema changed -- a published schema file never changes "
                f"once committed; add {next_version}.v<N+1>.json instead and move the manifest's "
                f"schema: ref to it"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="git ref to compare the working tree's schemas against")
    args = parser.parse_args()

    errors = check_naming() + check_immutability(args.base)
    if errors:
        for err in errors:
            print(f"check_schema_immutability: {err}", file=sys.stderr)
        return 1

    print("check_schema_immutability: naming and immutability checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
