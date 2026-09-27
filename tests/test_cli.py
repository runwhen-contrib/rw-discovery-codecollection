"""Validates `rwdiscovery/cli.py` against platform-contract §7:

- `validate()`'s command rules, against the SAME test-vector table the papi
  validator is held to (both must reject/accept identically) -- loaded
  against the real `packs/kubernetes/pack.yaml` `cli` block, never a
  hand-copied dict, so a change there is exercised here too.
- pseudo-flag handling (`--grep`, logs' `--tail`/`--limit-bytes` defaults
  and clamping).
- `run_cli()`'s executor, against a fake `kubectl` -- a small script this
  test writes to `tmp_path` and points at directly (`kubectl_path`), or
  puts first on `PATH` -- never a real cluster or a real kubectl binary.
"""

from __future__ import annotations

import os
import shlex
import sys
import textwrap
from pathlib import Path

import pytest

from rwdiscovery import cli
from rwdiscovery.packbuild import load_pack_yaml

CLI_BLOCK = load_pack_yaml()["cli"]


def _validate(command: str) -> cli.CliValidation:
    """Rule 1's other half: `shlex.split(command, posix=True)`, exactly as
    a client's raw string arrives before either validator ever sees it."""
    return cli.validate(shlex.split(command, posix=True), CLI_BLOCK)


def _write_fake_kubectl(tmp_path: Path, body: str, name: str = "fake-kubectl") -> Path:
    script = tmp_path / name
    script.write_text(f"#!{sys.executable}\n{textwrap.dedent(body)}")
    script.chmod(0o755)
    return script


KUBECONFIG_YAML = "apiVersion: v1\nkind: Config\n"

# --- platform-contract §7's shared test vectors -----------------------------
# Identical table to the papi validator's own copy.

_OK_VECTORS = [
    "get pods -n x",
    "kubectl logs deploy/x -n y --since=15m --grep=error",
    "logs deploy/x -n y",
    "auth can-i list pods -n x",
    "rollout history deploy/x -n y",
    "get secret -n x",
    "get secrets -o name",
    "get secret/s1 -o wide",
]


@pytest.mark.parametrize("command", _OK_VECTORS)
def test_shared_vectors_ok(command):
    result = _validate(command)
    assert result.ok, result.rejection


@pytest.mark.parametrize("command", ["delete pod x", "exec -it x -- sh", "rollout restart deploy/x"])
def test_shared_vectors_verb_not_allowed(command):
    result = _validate(command)
    assert not result.ok
    assert result.rejection.reason == "verb-not-allowed"


@pytest.mark.parametrize("command", ["get pods | grep x", "get pods; rm -rf /", "get pods $(id)"])
def test_shared_vectors_no_shell(command):
    result = _validate(command)
    assert not result.ok
    assert result.rejection.reason == "no-shell"


@pytest.mark.parametrize("command", ["get pods --kubeconfig=/tmp/k", "get pods --as admin", "logs -f deploy/x"])
def test_shared_vectors_flag_not_allowed(command):
    result = _validate(command)
    assert not result.ok
    assert result.rejection.reason == "flag-not-allowed"


@pytest.mark.parametrize(
    "command",
    ["get secret s1 -o yaml", "get secrets.v1 -o jsonpath={.data}", "get secret,pods -o json"],
)
def test_shared_vectors_sensitive_type(command):
    result = _validate(command)
    assert not result.ok
    assert result.rejection.reason == "sensitive-type"


def test_shared_vectors_invalid_grep_regex():
    result = _validate("logs deploy/x --grep=(")
    assert not result.ok
    assert result.rejection.reason == "invalid-grep"


@pytest.mark.parametrize("command", ["", "kubectl"])
def test_shared_vectors_empty_command(command):
    result = _validate(command)
    assert not result.ok
    assert result.rejection.reason == "empty"


# --- the specific per-vector shape the table's "result" column describes ---


def test_get_pods_resolves_verb_get():
    result = _validate("get pods -n x")
    assert result.verb == "get"
    assert result.argv == ["get", "pods", "-n", "x"]


def test_auth_can_i_is_a_two_word_verb():
    result = _validate("auth can-i list pods -n x")
    assert result.verb == "auth can-i"
    assert result.argv == ["auth", "can-i", "list", "pods", "-n", "x"]


def test_rollout_history_is_a_two_word_verb():
    result = _validate("rollout history deploy/x -n y")
    assert result.verb == "rollout history"
    assert result.argv == ["rollout", "history", "deploy/x", "-n", "y"]


def test_logs_with_since_and_grep_strips_grep_keeps_since_adds_limit_bytes_only():
    result = _validate("kubectl logs deploy/x -n y --since=15m --grep=error")
    assert result.ok
    assert result.verb == "logs"
    assert result.grep.pattern == "error"
    assert "--grep=error" not in result.argv
    assert "--since=15m" in result.argv
    assert "--tail=200" not in result.argv  # --since was already given
    assert f"--limit-bytes={4 * CLI_BLOCK['output']['defaultBytes']}" in result.argv


def test_logs_without_tail_or_since_gets_both_defaults():
    result = _validate("logs deploy/x -n y")
    assert result.ok
    assert result.argv[-2:] == ["--tail=200", f"--limit-bytes={4 * CLI_BLOCK['output']['defaultBytes']}"]


# --- pseudo-flags: --grep (both forms), logs defaults and clamping ---------


def test_grep_space_form_is_extracted_and_stripped():
    result = _validate("get pods -n x --grep foo")
    assert result.ok
    assert result.grep.pattern == "foo"
    assert "--grep" not in result.argv
    assert "foo" not in result.argv


def test_grep_equals_form_is_extracted_and_stripped():
    result = _validate("get pods -n x --grep=foo")
    assert result.ok
    assert result.grep.pattern == "foo"
    assert not any(tok.startswith("--grep") for tok in result.argv)


def test_grep_is_case_insensitive():
    result = _validate("get pods --grep=Foo")
    assert result.grep.search("a FOO line")


def test_logs_tail_given_is_left_alone_and_no_default_added():
    result = _validate("logs deploy/x --tail=50")
    assert result.argv.count("--tail=50") == 1
    assert not any(tok == "--tail=200" for tok in result.argv)


def test_logs_since_time_given_suppresses_the_tail_default():
    result = _validate("logs deploy/x --since-time=2024-01-01T00:00:00Z")
    assert not any(tok.startswith("--tail=") for tok in result.argv)


def test_logs_limit_bytes_default_is_four_times_the_default_max_bytes():
    result = cli.validate(["logs", "deploy/x"], CLI_BLOCK)
    assert f"--limit-bytes={4 * CLI_BLOCK['output']['defaultBytes']}" in result.argv


def test_logs_limit_bytes_default_uses_the_requested_max_bytes():
    requested = 20000
    result = cli.validate(["logs", "deploy/x"], CLI_BLOCK, max_bytes=requested)
    assert f"--limit-bytes={4 * requested}" in result.argv


def test_logs_given_limit_bytes_is_clamped_down_to_four_times_max_bytes():
    result = cli.validate(["logs", "deploy/x", "--limit-bytes=999999999"], CLI_BLOCK)
    expected = 4 * CLI_BLOCK["output"]["defaultBytes"]
    assert f"--limit-bytes={expected}" in result.argv
    assert result.argv.count("--limit-bytes=" + str(expected)) == 1


def test_logs_given_limit_bytes_below_the_max_is_left_at_its_own_value():
    result = cli.validate(["logs", "deploy/x", "--limit-bytes=1000"], CLI_BLOCK)
    assert "--limit-bytes=1000" in result.argv


def test_max_bytes_request_is_clamped_to_the_pack_maximum():
    huge = CLI_BLOCK["output"]["maxBytes"] * 10
    result = cli.validate(["logs", "deploy/x"], CLI_BLOCK, max_bytes=huge)
    assert result.max_bytes == CLI_BLOCK["output"]["maxBytes"]


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


def test_run_cli_applies_grep_before_the_cap_and_strips_it_before_exec(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import sys
        if any(a.startswith("--grep") for a in sys.argv[1:]):
            sys.stderr.write("received --grep, should have been stripped before exec\\n")
            sys.exit(2)
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
    assert not any(tok.startswith("--grep") for tok in result["argv"])


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


def test_run_cli_rejects_a_disallowed_argv_and_never_execs(tmp_path):
    script = _write_fake_kubectl(
        tmp_path,
        """
        import pathlib, sys
        pathlib.Path(sys.argv[0]).with_name("EXECUTED").touch()
        """,
    )
    result = cli.run_cli(
        kubeconfig_yaml=KUBECONFIG_YAML,
        argv=["delete", "pod", "x"],
        workdir=tmp_path / "work",
        cli_block=CLI_BLOCK,
        kubectl_path=str(script),
    )
    assert result["exitCode"] == -1
    assert result["rejected"] == {"reason": "verb-not-allowed", "hint": "verb not allowed: 'delete'"}
    assert result["stdout"] == ""
    assert not (tmp_path / "EXECUTED").exists()
