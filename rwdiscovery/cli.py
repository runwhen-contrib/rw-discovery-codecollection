"""The `cli` task (platform-contract §7): one allow-listed, read-only
kubectl command, exec'd for real -- the one place this capability shells
out to anything. Everything else in this package talks to the Kubernetes
API directly (see `k8s_client.py`'s docstring); `cli` exists precisely
because an agent wants the real `kubectl` output, not this capability's
own rendering of it.

Two halves:

- `validate()` -- the command rules, identical to papi's own copy (shared
  test vectors, `tests/test_cli.py`). Both validators read the same
  `cli:` block from `packs/kubernetes/pack.yaml` (`packbuild.load_pack_yaml()`
  here); papi's copy exists for early, helpful errors, but this one is
  authoritative -- `run_cli()` always re-validates from scratch and never
  execs anything it rejects.
- `run_cli()` -- writes the `kubeconfig` credential to a 0600 file inside
  the request's own scope directory (same convention as
  `credentials.py.build_api_client`), execs the real `kubectl` binary with
  a scrubbed environment and a wall-clock timeout, and deletes the file
  again once it's done.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import packbuild

# Rule 2: any of these as a whole token, or as a token's own prefix, means
# "this isn't one kubectl command any more" -- checked against every token,
# verb and flags alike, before anything else.
_SHELL_METACHARS = ("||", "&&", ">>", "|", "&", ";", ">", "<", "$(", "`")

# Rule 6: pseudo-flags this capability understands and strips before exec --
# never real kubectl flags, so `denyFlags` (rule 4) never has to know about
# them.
_GREP_FLAGS = ("--grep",)
_TAIL_FLAGS = ("--tail",)
_SINCE_FLAGS = ("--since", "--since-time")
_LIMIT_BYTES_FLAGS = ("--limit-bytes",)
_OUTPUT_FLAGS = ("-o", "--output")
_LOGS_DEFAULT_TAIL = 200

_STDERR_CAP_BYTES = 4 * 1024
# Wall-clock slack past the (already-clamped) request timeout, before the
# subprocess is killed outright -- covers kubectl's own shutdown/flush, not
# extra work.
_KILL_GRACE_SECONDS = 2


@dataclass(frozen=True)
class CliRejection:
    reason: str
    hint: str


@dataclass(frozen=True)
class CliValidation:
    """`ok=False` carries `rejection` only -- never a usable `argv`; a
    rejected command must never reach `subprocess`. `max_bytes` is the
    effective value this validation resolved (§1's `output.defaultBytes`/
    `maxBytes`, clamped) -- `run_cli` reuses it to cap the actual read
    rather than resolving it a second time."""

    ok: bool
    verb: str | None = None
    argv: list[str] | None = None  # exec-ready: no leading "kubectl", pseudo-flags resolved
    grep: re.Pattern[str] | None = None
    max_bytes: int | None = None
    rejection: CliRejection | None = None


def _reject(reason: str, hint: str) -> CliValidation:
    return CliValidation(ok=False, rejection=CliRejection(reason=reason, hint=hint))


def _has_shell_metachar(token: str) -> bool:
    """A metacharacter as the WHOLE token (`|`, split out on its own by
    whitespace) or glued to a word on either side, with no space at all
    (`pods;`, `$(id)`) -- `shlex.split` only ever separates on whitespace
    and quoting, never on these characters themselves, so a metacharacter
    with no space around it survives inside an ordinary word's token."""
    return any(token == m or token.startswith(m) or token.endswith(m) for m in _SHELL_METACHARS)


def _resolve_verb(tokens: list[str], verbs: list[str]) -> tuple[str, int] | None:
    """`(verb, token_count)` -- `token_count` is however many of `tokens`'
    leading elements the matched verb consumed (1, or 2 for a two-word verb
    like `auth can-i`)."""
    if len(tokens) >= 2:
        two = f"{tokens[0]} {tokens[1]}"
        if two in verbs:
            return two, 2
    if tokens and tokens[0] in verbs:
        return tokens[0], 1
    return None


def _find_flag(tokens: list[str], names: tuple[str, ...]) -> tuple[int, str] | None:
    """The first occurrence of any flag in `names`, as `(index, value)` --
    `value` from `--flag=value`, or the following token for a bare
    `--flag value` (`""` if the flag is the last token, with no value at
    all)."""
    for i, tok in enumerate(tokens):
        for name in names:
            if tok == name:
                return i, (tokens[i + 1] if i + 1 < len(tokens) else "")
            if tok.startswith(f"{name}="):
                return i, tok[len(name) + 1 :]
    return None


def _remove_flag_at(tokens: list[str], index: int) -> None:
    """Removes the flag token at `index` in place -- and the following
    value token too, when it was given as `--flag value` rather than
    `--flag=value` (no `=` in the flag token itself)."""
    span = 2 if "=" not in tokens[index] else 1
    del tokens[index : index + span]


def _resource_arg(args: list[str]) -> str | None:
    """Rule 5's resource arg: the first non-flag token after the verb."""
    for tok in args:
        if not tok.startswith("-"):
            return tok
    return None


def _is_sensitive_get(resource_arg: str, sensitive_types: list[str]) -> bool:
    """Each comma-separated resource name, with its `/object-name` suffix
    and `.group` suffix stripped, checked against `sensitiveTypes` --
    `secret/s1`, `secrets.v1` and `secret,pods` (any one of them) all
    resolve to a plain `secret`/`secrets`."""
    for item in resource_arg.split(","):
        name = item.split("/", 1)[0].split(".", 1)[0]
        if name in sensitive_types:
            return True
    return False


def resolve_max_bytes(requested: int | None, output: dict) -> int:
    if requested is None:
        return output["defaultBytes"]
    return min(requested, output["maxBytes"])


def resolve_timeout_seconds(requested: int | None, output: dict) -> int:
    if requested is None:
        return output["timeoutSeconds"]
    return min(requested, output["maxTimeoutSeconds"])


def validate(argv: list[str], cli_block: dict, max_bytes: int | None = None) -> CliValidation:
    """Platform-contract §7's command rules, in order. `argv` is already
    split on whitespace (`shlex.split(command, posix=True)` -- rule 1's
    other half) but may still carry a leading `kubectl` token and the raw
    `--grep`/logs pseudo-flags, exactly as a client typed them."""
    tokens = list(argv)
    if tokens and tokens[0] == "kubectl":
        tokens = tokens[1:]
    if not tokens:
        return _reject("empty", "empty command")

    for tok in tokens:
        if _has_shell_metachar(tok):
            return _reject("no-shell", "no shell: one kubectl command per call; use --grep to filter lines")

    resolved = _resolve_verb(tokens, cli_block["verbs"])
    if resolved is None:
        return _reject("verb-not-allowed", f"verb not allowed: {tokens[0]!r}")
    verb, verb_tokens = resolved
    args = tokens[verb_tokens:]

    for tok in args:
        for flag in cli_block["denyFlags"]:
            if tok == flag or tok.startswith(f"{flag}="):
                return _reject("flag-not-allowed", f"flag not allowed: {flag}")

    if verb == "get":
        resource_arg = _resource_arg(args)
        if resource_arg and _is_sensitive_get(resource_arg, cli_block["sensitiveTypes"]):
            output_hit = _find_flag(args, _OUTPUT_FLAGS)
            output_value = output_hit[1] if output_hit else None
            if output_value not in (None, "name", "wide"):
                return _reject(
                    "sensitive-type",
                    f"{resource_arg} is sensitive: only the default table, -o name, or -o wide are allowed",
                )

    # Rule 6: pseudo-flags, resolved and stripped last -- everything above
    # validates the command exactly as given.
    remaining = list(args)
    grep_re: re.Pattern[str] | None = None
    grep_hit = _find_flag(remaining, _GREP_FLAGS)
    if grep_hit is not None:
        index, pattern = grep_hit
        try:
            grep_re = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return _reject("invalid-grep", f"invalid grep regex: {exc}")
        _remove_flag_at(remaining, index)

    effective_max_bytes = resolve_max_bytes(max_bytes, cli_block["output"])

    if verb == "logs":
        has_tail_or_since = _find_flag(remaining, _TAIL_FLAGS) or _find_flag(remaining, _SINCE_FLAGS)
        if not has_tail_or_since:
            remaining.append(f"--tail={_LOGS_DEFAULT_TAIL}")

        limit = 4 * effective_max_bytes
        limit_hit = _find_flag(remaining, _LIMIT_BYTES_FLAGS)
        if limit_hit is None:
            remaining.append(f"--limit-bytes={limit}")
        else:
            index, value = limit_hit
            try:
                clamped = min(int(value), limit)
            except ValueError:
                clamped = limit
            _remove_flag_at(remaining, index)
            remaining.append(f"--limit-bytes={clamped}")

    exec_argv = [*verb.split(" "), *remaining]
    return CliValidation(ok=True, verb=verb, argv=exec_argv, grep=grep_re, max_bytes=effective_max_bytes)


def _drain_capped(stream, max_bytes: int, grep_re: re.Pattern[str] | None) -> tuple[bytes, bool]:
    """Reads `stream` (a binary pipe) line by line, filtering each line
    through `grep_re` BEFORE counting it against `max_bytes` -- a dropped
    line never consumes any of the budget. Stops once `max_bytes` of
    matching output has been captured, but keeps draining the rest of the
    stream (never storing it) so the process can still exit instead of
    blocking on a full pipe."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for line in iter(stream.readline, b""):
        if grep_re is not None and not grep_re.search(line.decode("utf-8", "replace")):
            continue
        if total + len(line) > max_bytes:
            remaining = max_bytes - total
            if remaining > 0:
                chunks.append(line[:remaining])
                total += remaining
            truncated = True
            for _ in iter(stream.readline, b""):
                pass  # drain without storing, so the process isn't left blocked on a full pipe
            break
        chunks.append(line)
        total += len(line)
    return b"".join(chunks), truncated


def _run_drain(stream, max_bytes: int, grep_re: re.Pattern[str] | None, box: dict) -> None:
    box["data"], box["truncated"] = _drain_capped(stream, max_bytes, grep_re)


def run_cli(
    *,
    kubeconfig_yaml: str,
    argv: list[str],
    workdir: Path,
    max_bytes: int | None = None,
    timeout_seconds: int | None = None,
    cli_block: dict | None = None,
    kubectl_path: str = "kubectl",
) -> dict:
    """Platform-contract §7's executor -- `rw.cli_result.v1`. Re-validates
    `argv` from scratch against the pack's own `cli` block, regardless of
    what papi already checked (the edge is authoritative): a rejected
    `argv` returns here with `exitCode: -1` and never reaches `subprocess`.

    `kubectl_path` is a test seam (an injectable executable path); in
    production it's the bare `"kubectl"` name, resolved via the scrubbed
    child environment's own `PATH`.
    """
    cli_block = cli_block if cli_block is not None else packbuild.load_pack_yaml()["cli"]
    validation = validate(argv, cli_block, max_bytes=max_bytes)
    if not validation.ok:
        return {
            "argv": list(argv),
            "exitCode": -1,
            "stdout": "",
            "stderr": "",
            "truncated": False,
            "stdoutBytes": 0,
            "durationMs": 0,
            "rejected": {"reason": validation.rejection.reason, "hint": validation.rejection.hint},
        }

    effective_timeout = resolve_timeout_seconds(timeout_seconds, cli_block["output"])

    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    fd, kubeconfig_path = tempfile.mkstemp(dir=workdir, prefix=".kubeconfig-", suffix=".yaml")
    os.chmod(kubeconfig_path, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(kubeconfig_yaml)

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "KUBECONFIG": kubeconfig_path,
        }
        resolved_kubectl = shutil.which(kubectl_path, path=env["PATH"]) or kubectl_path
        cmd = [
            resolved_kubectl,
            "--kubeconfig",
            kubeconfig_path,
            f"--request-timeout={effective_timeout}s",
            *validation.argv,
        ]

        start = time.monotonic()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, shell=False)  # noqa: S603

        stdout_box: dict = {}
        stderr_box: dict = {}
        stdout_thread = threading.Thread(
            target=_run_drain, args=(proc.stdout, validation.max_bytes, validation.grep, stdout_box), daemon=True
        )
        stderr_thread = threading.Thread(
            target=_run_drain, args=(proc.stderr, _STDERR_CAP_BYTES, None, stderr_box), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        killed = False
        try:
            proc.wait(timeout=effective_timeout + _KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            killed = True

        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        stdout_bytes = stdout_box.get("data", b"")
        stderr_bytes = stderr_box.get("data", b"")
        truncated = killed or stdout_box.get("truncated", False) or stderr_box.get("truncated", False)

        return {
            "argv": validation.argv,
            "exitCode": proc.returncode,
            "stdout": stdout_bytes.decode("utf-8", "replace"),
            "stderr": stderr_bytes.decode("utf-8", "replace"),
            "truncated": truncated,
            "stdoutBytes": len(stdout_bytes),
            "durationMs": int((time.monotonic() - start) * 1000),
            "rejected": None,
        }
    finally:
        try:
            os.unlink(kubeconfig_path)
        except OSError:
            pass
