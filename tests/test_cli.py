"""Validates `rwdiscovery/cli.py` against platform-contract §7:

- `validate()`'s allow-list rules, against the SAME shared vector file the
  platform's own validator is held to (`tests/cli_vectors.json`, a verbatim
  copy -- never edit it here alone) -- loaded against the real
  `packs/kubernetes/pack.yaml` `cli` block, never a hand-copied dict, so a
  change there is exercised here too.
- `run_cli()`'s executor, against a fake `kubectl` -- a small script this
  test writes to `tmp_path` and points at directly (`kubectl_path`), or
  puts first on `PATH` -- never a real cluster or a real kubectl binary.
  Every execution test asserts the exact argv the fake received: the
  executor's own `--kubeconfig`/`--request-timeout`, then the normalised
  argv, and nothing else.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import textwrap
from pathlib import Path

import pytest

from rwdiscovery import cli
from rwdiscovery.packbuild import load_pack_yaml

CLI_BLOCK = load_pack_yaml()["cli"]

VECTORS = json.loads((Path(__file__).resolve().parent / "cli_vectors.json").read_text())
MAX_BYTES = VECTORS["maxBytes"]
OK_CASES = [case for case in VECTORS["cases"] if case["ok"]]
REJECTED_CASES = [case for case in VECTORS["cases"] if not case["ok"]]
SPLITTABLE_CASES = [case for case in VECTORS["cases"] if case.get("reason") != "unparsable"]

DEFAULT_LIMIT_BYTES = 4 * CLI_BLOCK["output"]["defaultBytes"]
DEFAULT_TIMEOUT = CLI_BLOCK["output"]["timeoutSeconds"]

KUBECONFIG_YAML = "apiVersion: v1\nkind: Config\n"

# Prepended to every fake kubectl: records exactly the argv it was exec'd
# with, next to the script, before the test's own body runs.
_RECORD_ARGV = """\
import json as _json, pathlib as _pathlib, sys as _sys
_pathlib.Path(_sys.argv[0]).with_name("received-argv.json").write_text(_json.dumps(_sys.argv[1:]))
"""


def _write_fake_kubectl(tmp_path: Path, body: str, name: str = "fake-kubectl") -> Path:
    script = tmp_path / name
    script.write_text(f"#!{sys.executable}\n{_RECORD_ARGV}{textwrap.dedent(body)}")
    script.chmod(0o755)
    return script


def _received_argv(tmp_path: Path) -> list[str]:
    return json.loads((tmp_path / "received-argv.json").read_text())


def _assert_exec_argv(tmp_path: Path, normalised: list[str], timeout: int = DEFAULT_TIMEOUT) -> None:
    """The fake kubectl received `--kubeconfig <file> --request-timeout=<t>s` and then exactly `normalised`."""
    received = _received_argv(tmp_path)
    assert received[0] == "--kubeconfig"
    assert Path(received[1]).name.startswith(".kubeconfig-")
    assert received[2] == f"--request-timeout={timeout}s"
    assert received[3:] == normalised


# --- the shared vector file: every case, both outcomes -----------------------


@pytest.mark.parametrize("case", OK_CASES, ids=[case["command"] for case in OK_CASES])
def test_shared_vector_ok(case):
    result = cli.validate(case["command"], CLI_BLOCK, max_bytes=MAX_BYTES)
    assert result.ok, result.rejection
    assert result.verb == case["verb"]
    assert result.argv == case["argv"]
    assert (result.grep.pattern if result.grep else None) == case["grep"]


@pytest.mark.parametrize("case", REJECTED_CASES, ids=[case["command"] or "<empty>" for case in REJECTED_CASES])
def test_shared_vector_rejected(case):
    result = cli.validate(case["command"], CLI_BLOCK, max_bytes=MAX_BYTES)
    assert not result.ok
    assert result.argv is None
    assert result.rejection.reason == case["reason"]
    assert result.rejection.hint


@pytest.mark.parametrize("case", SPLITTABLE_CASES, ids=[case["command"] or "<empty>" for case in SPLITTABLE_CASES])
def test_pre_split_tokens_validate_exactly_like_the_command_string(case):
    """The platform sends the shell-split tokens, not the string -- same
    outcome either way (an unparsable command never reaches the capability
    as tokens, so it has no token form to compare)."""
    from_string = cli.validate(case["command"], CLI_BLOCK, max_bytes=MAX_BYTES)
    from_tokens = cli.validate(shlex.split(case["command"], posix=True), CLI_BLOCK, max_bytes=MAX_BYTES)
    assert from_tokens == from_string


def test_the_vector_file_covers_every_reason_code():
    assert {case["reason"] for case in REJECTED_CASES} == {
        "empty",
        "unparsable",
        "no-shell",
        "verb-not-allowed",
        "flag-not-allowed",
        "missing-value",
        "bad-value",
        "output-not-allowed",
        "sensitive-type",
        "invalid-grep",
    }


# --- hints: what the agent reads back to fix its own command -----------------


def _rejection(command: str) -> cli.CliRejection:
    result = cli.validate(command, CLI_BLOCK, max_bytes=MAX_BYTES)
    assert not result.ok
    return result.rejection


def test_a_long_flag_not_allowed_names_the_flag_and_lists_the_verbs_flags():
    rejection = _rejection("get pods --server=https://evil.example.com")
    assert rejection.reason == "flag-not-allowed"
    assert rejection.hint.startswith("--server is not allowed for get; allowed: ")
    assert "--namespace (-n)" in rejection.hint
    assert "--field-selector" in rejection.hint
    assert "--previous" not in rejection.hint


def test_a_short_flag_not_allowed_names_the_short_flag():
    rejection = _rejection("get pods -shttps://evil.example.com")
    assert rejection.hint.startswith("-s is not allowed for get; allowed: ")
    assert "--output (-o)" in rejection.hint


def test_a_verb_with_no_flags_says_so():
    assert _rejection("api-versions -n x").hint == "-n is not allowed for api-versions; allowed: none"


def test_double_dash_hint():
    assert _rejection("get pods -- --kubeconfig=/x").hint == "-- is not allowed"


def test_a_repeated_output_says_given_twice():
    assert "given twice" in _rejection("get pods -o yaml -o json").hint


def test_no_shell_hint():
    assert _rejection("get pods | grep x").hint == "no shell: one command per call; use --grep to filter lines"


def test_output_not_allowed_lists_the_verbs_outputs():
    assert "plaintext, plaintext-openapiv2" in _rejection("explain pods -o yaml").hint


def test_sensitive_type_hint():
    assert (
        _rejection("get Secret s1 -o yaml").hint
        == "secret is sensitive: only the default table, -o name or -o wide are allowed"
    )


# --- edge cases beyond the vector file ----------------------------------------


def test_grep_is_case_insensitive():
    result = cli.validate("logs deploy/x --grep=Foo", CLI_BLOCK)
    assert result.grep.search("a FOO line")


def test_grep_two_token_form_is_extracted_and_stripped():
    result = cli.validate(["logs", "deploy/x", "--grep", "connection refused"], CLI_BLOCK)
    assert result.grep.pattern == "connection refused"
    assert result.argv == ["logs", "deploy/x", "--tail=200", f"--limit-bytes={DEFAULT_LIMIT_BYTES}"]


def test_grep_is_not_allowed_on_a_verb_that_does_not_list_it():
    assert _rejection("get pods --grep=x").reason == "flag-not-allowed"


def test_a_value_flag_takes_the_next_token_even_when_it_looks_like_a_flag():
    result = cli.validate("get pods -n --kubeconfig=/x", CLI_BLOCK)
    assert result.argv == ["get", "pods", "--namespace=--kubeconfig=/x"]


def test_a_boolean_given_with_an_upper_case_value_is_normalised():
    assert cli.validate("get pods --show-labels=TRUE", CLI_BLOCK).argv == ["get", "pods", "--show-labels=true"]


def test_a_dash_not_followed_by_a_letter_is_a_positional():
    assert cli.validate("get pods -1", CLI_BLOCK).argv == ["get", "pods", "-1"]


def test_logs_limit_bytes_default_uses_the_requested_max_bytes():
    result = cli.validate(["logs", "deploy/x"], CLI_BLOCK, max_bytes=20000)
    assert result.argv == ["logs", "deploy/x", "--tail=200", "--limit-bytes=80000"]


def test_logs_given_limit_bytes_below_the_max_is_kept_in_place():
    result = cli.validate(["logs", "deploy/x", "--limit-bytes=1000", "--tail=5"], CLI_BLOCK)
    assert result.argv == ["logs", "deploy/x", "--limit-bytes=1000", "--tail=5"]


def test_max_bytes_request_is_clamped_to_the_pack_maximum():
    huge = CLI_BLOCK["output"]["maxBytes"] * 10
    result = cli.validate(["logs", "deploy/x"], CLI_BLOCK, max_bytes=huge)
    assert result.max_bytes == CLI_BLOCK["output"]["maxBytes"]
    assert result.argv[-1] == f"--limit-bytes={4 * CLI_BLOCK['output']['maxBytes']}"


# --- run_cli(): execution against a fake kubectl ----------------------------


def test_run_cli_captures_stdout_and_exit_code(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        sys.stdout.write("hello world\\n")
        sys.exit(0)
        """,
    )
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods", "-n", "x"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert result["rejected"] is None
    assert result["exitCode"] == 0
    assert result["stdout"] == "hello world\n"
    assert result["truncated"] is False
    assert result["argv"] == ["get", "pods", "--namespace=x"]
    _assert_exec_argv(tmp_path, ["get", "pods", "--namespace=x"])


def test_run_cli_execs_only_the_normalised_argv(tmp_path):
    """Short clusters, `-o<value>` and two-token values all reach kubectl as `--name=value` only."""
    script = _write_fake_kubectl(tmp_path, "")
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["kubectl", "get", "-Al", "app=web", "pods", "-oyaml", "--sort-by", ".metadata.name"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    expected = ["get", "pods", "--all-namespaces", "--selector=app=web", "--output=yaml", "--sort-by=.metadata.name"]
    assert result["argv"] == expected
    _assert_exec_argv(tmp_path, expected)


def test_run_cli_nonzero_exit_code_is_reported(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        sys.exit(7)
        """,
    )
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert result["exitCode"] == 7
    _assert_exec_argv(tmp_path, ["get", "pods"])


def test_run_cli_truncates_stdout_at_max_bytes(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        sys.stdout.write("0123456789ABCDEFGHIJ\\n")
        """,
    )
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods"],
        workdir=tmp_path / "work",
        max_bytes=10,
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert result["stdout"] == "0123456789"
    assert result["stdoutBytes"] == 10
    assert result["truncated"] is True
    _assert_exec_argv(tmp_path, ["get", "pods"])


def test_run_cli_applies_grep_before_the_cap_and_strips_it_before_exec(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        for line in ["line one ok", "line two ERROR bad", "line three fine", "line four ERROR again"]:
            sys.stdout.write(line + "\\n")
        """,
    )
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["logs", "deploy/x", "-n", "y", "--since=1h", "--grep=ERROR"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert result["exitCode"] == 0
    assert result["stdout"] == "line two ERROR bad\nline four ERROR again\n"
    expected = ["logs", "deploy/x", "--namespace=y", "--since=1h", f"--limit-bytes={DEFAULT_LIMIT_BYTES}"]
    assert result["argv"] == expected
    _assert_exec_argv(tmp_path, expected)


def test_run_cli_caps_stderr_at_four_kb(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        sys.stderr.write("e" * 8000)
        sys.exit(0)
        """,
    )
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert len(result["stderr"].encode()) == 4 * 1024
    assert result["stderr"] == "e" * (4 * 1024)
    assert result["truncated"] is True
    _assert_exec_argv(tmp_path, ["get", "pods"])


def test_run_cli_kills_on_timeout(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys, time
        time.sleep(5)
        sys.stdout.write("should never get here\\n")
        """,
    )
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods"],
        workdir=tmp_path / "work",
        timeout_seconds=1,
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert result["exitCode"] < 0  # killed by signal, never the fake script's own exit
    assert result["truncated"] is True
    assert result["stdout"] == ""
    assert result["durationMs"] < 4500  # well short of the fake script's 5s sleep
    _assert_exec_argv(tmp_path, ["get", "pods"], timeout=1)


def test_run_cli_writes_kubeconfig_0600_and_removes_it_after(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import os, stat, sys
        argv = sys.argv[1:]
        path = argv[argv.index("--kubeconfig") + 1]
        mode = stat.S_IMODE(os.stat(path).st_mode)
        sys.stdout.write(f"MODE:{oct(mode)}\\n")
        """,
    )
    workdir = tmp_path / "work"
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods"],
        workdir=workdir,
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert "MODE:0o600" in result["stdout"]
    assert not list(workdir.glob(".kubeconfig-*"))
    assert Path(_received_argv(tmp_path)[1]).parent == workdir


def test_run_cli_scrubs_the_environment(tmp_path, monkeypatch):
    """A plain `/bin/sh` script here, not the Python-shebang fake the other
    execution tests use: an interpreter's own startup adds a few bookkeeping
    vars of its own regardless of what a parent passes it (`/bin/sh` sets
    `PWD`/`SHLVL`/`_`; CPython does its own locale coercion, PEP 538) --
    harmless noise neither this test nor `run_cli` controls, so the
    assertion below checks for the one thing that actually matters: nothing
    from the *parent's* environment beyond PATH/HOME/KUBECONFIG reaches the
    child."""
    monkeypatch.setenv("RWDISCOVERY_TEST_SECRET", "leak-me")
    script = tmp_path / "fake-kubectl"
    script.write_text("#!/bin/sh\nenv\n")
    script.chmod(0o755)
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    seen = {line.split("=", 1)[0] for line in result["stdout"].splitlines() if "=" in line}
    assert {"PATH", "HOME", "KUBECONFIG"} <= seen
    assert "RWDISCOVERY_TEST_SECRET" not in result["stdout"]


def test_run_cli_resolves_kubectl_via_path_when_given_the_bare_name(tmp_path, monkeypatch):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        sys.stdout.write("via-path\\n")
        """,
        name="kubectl",
    )
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["get", "pods"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        # kubectl_path defaults to the bare "kubectl" name
    )
    assert result["stdout"] == "via-path\n"
    assert script.exists()
    _assert_exec_argv(tmp_path, ["get", "pods"])


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (["delete", "pod", "x"], "verb-not-allowed"),
        (["get", "pods", "-shttps://evil.example.com"], "flag-not-allowed"),
        (["get", "pods", "--", "--kubeconfig=/x"], "flag-not-allowed"),
        (["get", "Secret", "s1", "-oyaml"], "sensitive-type"),
        (["get", "pods", "|", "sh"], "no-shell"),
    ],
)
def test_run_cli_rejects_a_disallowed_argv_and_never_execs(tmp_path, argv, reason):
    script = _write_fake_kubectl(tmp_path, "")
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=argv,
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert result["exitCode"] == -1
    assert result["rejected"]["reason"] == reason
    assert result["rejected"]["hint"]
    assert result["argv"] == argv
    assert result["stdout"] == ""
    assert not (tmp_path / "received-argv.json").exists()
