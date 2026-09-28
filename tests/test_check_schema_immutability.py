"""Unit-level coverage for scripts/check_schema_immutability.py -- the
naming and immutability rules docs/platform-contract.md's "versioned,
immutable schemas" section describes for every capabilities/*/schemas/ file.
Each test builds its own tiny, throwaway git repo under tmp_path (never this
repo's own history) so a real commit/checkout is exercised end to end, not
just string comparisons.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_schema_immutability.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_schema_immutability import (  # noqa: E402
    check_immutability,
    check_naming,
    is_base_resolvable,
)

SCHEMAS_DIR = "capabilities/k8s-discovery/schemas"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


def _init_repo(repo: Path) -> None:
    _git(repo, "init", "-q")
    # Local, throwaway identity -- never relies on this machine's own git config being set up.
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")


def _commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture
def repo_with_v1(tmp_path: Path) -> tuple[Path, str]:
    """A fresh git repo with one committed, versioned schema file."""
    _init_repo(tmp_path)
    schemas_dir = tmp_path / SCHEMAS_DIR
    schemas_dir.mkdir(parents=True)
    (schemas_dir / "athing.v1.json").write_text('{"a": 1, "b": 2}\n')
    base_sha = _commit_all(tmp_path, "add v1 schema")
    return tmp_path, base_sha


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------
def test_unchanged_file_passes(repo_with_v1: tuple[Path, str]):
    repo, base = repo_with_v1
    assert check_immutability(base, repo) == []


def test_changed_content_fails(repo_with_v1: tuple[Path, str]):
    repo, base = repo_with_v1
    (repo / SCHEMAS_DIR / "athing.v1.json").write_text('{"a": 999}\n')
    errors = check_immutability(base, repo)
    assert len(errors) == 1
    assert "athing.v1.json" in errors[0]


def test_whitespace_only_reformat_passes(repo_with_v1: tuple[Path, str]):
    # Same value, re-serialised with different whitespace/key order -- canonical JSON comparison
    # means this is not a change.
    repo, base = repo_with_v1
    (repo / SCHEMAS_DIR / "athing.v1.json").write_text('{\n  "b":    2,\n  "a": 1\n}\n')
    assert check_immutability(base, repo) == []


def test_deleted_file_fails(repo_with_v1: tuple[Path, str]):
    repo, base = repo_with_v1
    (repo / SCHEMAS_DIR / "athing.v1.json").unlink()
    errors = check_immutability(base, repo)
    assert len(errors) == 1
    assert "athing.v1.json" in errors[0]
    assert "deleted" in errors[0]


def test_new_version_added_alongside_old_passes(repo_with_v1: tuple[Path, str]):
    repo, base = repo_with_v1
    (repo / SCHEMAS_DIR / "athing.v2.json").write_text('{"a": 2}\n')
    assert check_immutability(base, repo) == []
    assert check_naming(repo) == []


def test_unversioned_file_at_base_deleted_passes(tmp_path: Path):
    # This is exactly what this PR itself does: retire an old, unversioned filename by deleting
    # it (git mv) in favour of a versioned one.
    _init_repo(tmp_path)
    schemas_dir = tmp_path / SCHEMAS_DIR
    schemas_dir.mkdir(parents=True)
    (schemas_dir / "athing.json").write_text('{"a": 1}\n')
    base = _commit_all(tmp_path, "old, unversioned schema name")

    (schemas_dir / "athing.json").unlink()
    (schemas_dir / "athing.v1.json").write_text('{"a": 1}\n')

    assert check_immutability(base, tmp_path) == []


# ---------------------------------------------------------------------------
# naming
# ---------------------------------------------------------------------------
def test_unversioned_new_file_fails_naming(repo_with_v1: tuple[Path, str]):
    repo, base = repo_with_v1
    (repo / SCHEMAS_DIR / "README.md").write_text("not a schema")
    errors = check_naming(repo)
    assert len(errors) == 1
    assert "README.md" in errors[0]
    # A brand-new file never existed at base, so immutability itself has nothing to say about it.
    assert check_immutability(base, repo) == []


def test_correctly_named_files_pass_naming(repo_with_v1: tuple[Path, str]):
    repo, _base = repo_with_v1
    assert check_naming(repo) == []


# ---------------------------------------------------------------------------
# unresolvable base -- first push of a branch
# ---------------------------------------------------------------------------
def test_empty_base_passes(repo_with_v1: tuple[Path, str]):
    repo, _base = repo_with_v1
    (repo / SCHEMAS_DIR / "athing.v1.json").write_text('{"a": 999}\n')  # would fail if compared
    assert not is_base_resolvable("", repo)
    assert check_immutability("", repo) == []


def test_all_zero_sha_base_passes(repo_with_v1: tuple[Path, str]):
    repo, _base = repo_with_v1
    (repo / SCHEMAS_DIR / "athing.v1.json").write_text('{"a": 999}\n')  # would fail if compared
    zero_sha = "0" * 40
    assert not is_base_resolvable(zero_sha, repo)
    assert check_immutability(zero_sha, repo) == []


def test_unresolvable_ref_passes(repo_with_v1: tuple[Path, str]):
    repo, _base = repo_with_v1
    assert not is_base_resolvable("not-a-real-ref", repo)
    assert check_immutability("not-a-real-ref", repo) == []


# ---------------------------------------------------------------------------
# CLI, against this repo's own real, checked-in schemas
# ---------------------------------------------------------------------------
def test_cli_passes_against_this_repos_own_schemas_at_head():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--base", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
