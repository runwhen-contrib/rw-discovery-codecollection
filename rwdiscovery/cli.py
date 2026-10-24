"""The `cli` task (platform-contract §7): one allow-listed, read-only
kubectl command, exec'd for real -- the one place this capability shells
out to anything. Everything else in this package talks to the Kubernetes
API directly (see `k8s_client.py`'s docstring); `cli` exists precisely
because an agent wants the real `kubectl` output, not this capability's
own rendering of it.

Two halves:

- `validate()` -- the command rules, identical to the platform's own copy
  (the same shared vector file, `tests/cli_vectors.json`). An **allow-list**,
  parsed the way kubectl's own flag parser (pflag) parses: the pack's `cli`
  block (`packs/kubernetes/pack.yaml`, loaded with
  `packbuild.load_pack_yaml()`) declares every flag kubectl may ever take and,
  per verb, the flags and `-o` values it allows; anything else is refused.
  A valid command comes back as a **normalised argv** -- every flag
  rewritten as `--name[=value]` -- and that argv is the only thing ever
  exec'd. The platform's copy exists for early, helpful errors; this one is
  authoritative -- `run_cli()` always re-validates from scratch and never
  execs anything it rejects.
- `run_cli()` -- writes the `kubeconfig` credential to a 0600 file inside
  the request's own scope directory (same convention as
  `credentials.py.build_api_client`), execs the real `kubectl` binary with
  a scrubbed environment and a wall-clock timeout, and deletes the file
  again once it's done. When the output had to be cut, the result also
  names the queued task (`export` or `logs`) that returns all of it
  (`full_output_for()`).
"""

from __future__ import annotations

import re
import shlex
import shutil
import string
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import packbuild
from .kubectl_artifact import kubeconfig_file, scrubbed_env

# Step 2: a token that is exactly one of these, starts with one of the
# prefixes, or ends with the suffix is shell syntax, not a kubectl argument.
# `shlex.split` only ever separates on whitespace and quoting, so `pods;`
# arrives as one token -- hence the suffix check.
_SHELL_TOKENS = frozenset({"|", "||", "&", "&&", ";", ">", ">>", "<", "<<"})
_SHELL_PREFIXES = ("$(", "`")
_SHELL_SUFFIX = ";"
_NO_SHELL_HINT = "no shell: one command per call; use --grep to filter lines"

_OUTPUT_FLAG = "output"
_GREP_FLAG = "grep"
# Step 4: every other flag may repeat.
_UNREPEATABLE_FLAGS = frozenset({_OUTPUT_FLAG, _GREP_FLAG})
_BOOLEAN_VALUES = frozenset({"true", "false"})

_GET_VERB = "get"
_LOGS_VERB = "logs"
_LOGS_WINDOW_FLAGS = frozenset({"tail", "since", "since-time"})
_LOGS_DEFAULT_TAIL = "--tail=200"
_LIMIT_BYTES_FLAG = "limit-bytes"
_INTEGER_RE = re.compile(r"-?[0-9]+")

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
    argv: list[str] | None = None  # the normalised argv: no leading "kubectl", pseudo-flags removed, defaults added
    grep: re.Pattern[str] | None = None
    max_bytes: int | None = None
    rejection: CliRejection | None = None


class _Rejected(Exception):
    """Raised by the rule helpers below; `validate()` turns it into a `CliValidation`."""

    def __init__(self, reason: str, hint: str) -> None:
        super().__init__(f"{reason}: {hint}")
        self.reason = reason
        self.hint = hint


@dataclass
class _Flag:
    """One flag occurrence, in order of appearance. `value` is `None` for a
    boolean given without `=`."""

    name: str
    value: str | None


def resolve_max_bytes(requested: int | None, output: dict) -> int:
    if requested is None:
        return output["defaultBytes"]
    return min(requested, output["maxBytes"])


def resolve_timeout_seconds(requested: int | None, output: dict) -> int:
    if requested is None:
        return output["timeoutSeconds"]
    return min(requested, output["maxTimeoutSeconds"])


def validate(command: str | list[str], cli_block: dict, max_bytes: int | None = None) -> CliValidation:
    """Platform-contract §7's rules, in order; the first violation wins.

    `command` is either the raw command string (split here with
    `shlex.split(command, posix=True)`) or the already-split tokens, exactly
    as the platform sends them in a request's `argv` -- a leading `kubectl`
    and the `--grep` pseudo-flag included. Both forms validate identically.
    """
    try:
        return _validate(command, cli_block, max_bytes)
    except _Rejected as exc:
        return CliValidation(ok=False, rejection=CliRejection(reason=exc.reason, hint=exc.hint))


def _validate(command: str | list[str], cli_block: dict, max_bytes: int | None) -> CliValidation:
    tokens = _tokenise(command, cli_block["name"])
    _reject_shell(tokens)
    verb, consumed = _match_verb(tokens, cli_block["verbs"])
    positionals, flags = _Walker(tokens[consumed:], verb=verb, cli_block=cli_block).run()
    verb_spec = cli_block["verbs"][verb]

    output = next((f.value for f in flags if f.name == _OUTPUT_FLAG), None)
    if output is not None:
        _check_output(output, verb=verb, outputs=verb_spec.get("outputs") or [])
    _check_sensitive(positionals, output=output, cli_block=cli_block)

    grep_re: re.Pattern[str] | None = None
    grep = next((f.value for f in flags if f.name == _GREP_FLAG), None)
    if grep is not None:
        try:
            grep_re = re.compile(grep, re.IGNORECASE)
        except re.error as exc:
            raise _Rejected("invalid-grep", f"--grep is not a valid regular expression: {exc}") from exc

    effective_max_bytes = resolve_max_bytes(max_bytes, cli_block["output"])
    defaults: list[str] = []
    if verb == _LOGS_VERB:
        defaults = _apply_logs_defaults(flags, limit=4 * effective_max_bytes)

    rendered = [_render(f) for f in flags if not _flag_spec(cli_block, f.name).get("pseudo", False)]
    argv = [*tokens[:consumed], *positionals, *rendered, *defaults]
    return CliValidation(ok=True, verb=verb, argv=argv, grep=grep_re, max_bytes=effective_max_bytes)


def _flag_spec(cli_block: dict, name: str) -> dict:
    """A `flags` entry; `{}` in the pack (a plain boolean) may load as `None`."""
    return cli_block["flags"][name] or {}


def _tokenise(command: str | list[str], name: str) -> list[str]:
    """Step 1: split (a string only), drop a leading binary name, reject an empty command."""
    if isinstance(command, str):
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            raise _Rejected("unparsable", f"the command could not be split into arguments: {exc}") from exc
    else:
        tokens = list(command)
    if tokens and tokens[0] == name:
        tokens = tokens[1:]
    if not tokens:
        raise _Rejected("empty", f"pass one {name} command, e.g. {name} get pods -n <namespace>")
    return tokens


def _reject_shell(tokens: list[str]) -> None:
    """Step 2. A `|` INSIDE a token (`--grep=ERROR|FATAL`) is a flag value, not a pipe."""
    for token in tokens:
        if token in _SHELL_TOKENS or token.startswith(_SHELL_PREFIXES) or token.endswith(_SHELL_SUFFIX):
            raise _Rejected("no-shell", _NO_SHELL_HINT)


def _match_verb(tokens: list[str], verbs: dict) -> tuple[str, int]:
    """Step 3: `(verb, token_count)` -- the two-word pair when THAT pair is a
    verb (`auth can-i`), else the first token."""
    if len(tokens) >= 2:
        two_word = f"{tokens[0]} {tokens[1]}"
        if two_word in verbs:
            return two_word, 2
    if tokens[0] in verbs:
        return tokens[0], 1
    raise _Rejected("verb-not-allowed", f"'{tokens[0]}' is not an allowed verb; allowed: {', '.join(verbs)}")


def _allowed_flags_hint(verb: str, cli_block: dict) -> str:
    shown = []
    for name in cli_block["verbs"][verb].get("flags") or []:
        short = _flag_spec(cli_block, name).get("short")
        shown.append(f"--{name} (-{short})" if short else f"--{name}")
    return ", ".join(shown) or "none"


class _Walker:
    """Step 4's left-to-right pass over the tokens after the verb, the way
    pflag reads them."""

    def __init__(self, args: list[str], *, verb: str, cli_block: dict) -> None:
        self.args = args
        self.i = 0
        self.verb = verb
        self.cli_block = cli_block
        self.allowed = set(cli_block["verbs"][verb].get("flags") or [])
        self.shorts = {
            _flag_spec(cli_block, name)["short"]: name
            for name in cli_block["flags"]
            if _flag_spec(cli_block, name).get("short")
        }
        self.positionals: list[str] = []
        self.flags: list[_Flag] = []

    def run(self) -> tuple[list[str], list[_Flag]]:
        while self.i < len(self.args):
            token = self.args[self.i]
            self.i += 1
            if token == "--":
                raise _Rejected("flag-not-allowed", "-- is not allowed")
            if token.startswith("--"):
                self._long(token)
            elif len(token) > 1 and token[0] == "-" and token[1] in string.ascii_letters:
                self._short_cluster(token)
            else:
                self.positionals.append(token)
        return self.positionals, self.flags

    def _resolve(self, name: str | None, shown: str) -> tuple[str, dict]:
        """The flag's name and spec, if this verb allows it and it isn't an
        unrepeatable repeat."""
        if name is None or name not in self.cli_block["flags"] or name not in self.allowed:
            raise _Rejected(
                "flag-not-allowed",
                f"{shown} is not allowed for {self.verb}; allowed: {_allowed_flags_hint(self.verb, self.cli_block)}",
            )
        if name in _UNREPEATABLE_FLAGS and any(f.name == name for f in self.flags):
            raise _Rejected("flag-not-allowed", f"--{name} given twice; pass it once")
        return name, _flag_spec(self.cli_block, name)

    def _next_value(self, shown: str) -> str:
        if self.i >= len(self.args):
            raise _Rejected("missing-value", f"{shown} needs a value")
        value = self.args[self.i]
        self.i += 1
        return value

    def _long(self, token: str) -> None:
        """`--name[=v]`."""
        given, has_equals, inline = token[2:].partition("=")
        name, spec = self._resolve(given, f"--{given}")
        value: str | None
        if spec.get("value", False):
            value = inline if has_equals else self._next_value(f"--{name}")
        elif has_equals:
            value = inline.lower()
            if value not in _BOOLEAN_VALUES:
                raise _Rejected("bad-value", f"--{name} takes true or false, not '{inline}'")
        else:
            value = None
        self.flags.append(_Flag(name, value))

    def _short_cluster(self, token: str) -> None:
        """`-abc`, `-ovalue`, `-o=value` or `-o value`: booleans continue the
        cluster, a value flag ends it."""
        for j in range(1, len(token)):
            ch = token[j]
            name, spec = self._resolve(self.shorts.get(ch), f"-{ch}")
            if not spec.get("value", False):
                self.flags.append(_Flag(name, None))
                continue
            rest = token[j + 1 :].removeprefix("=")
            self.flags.append(_Flag(name, rest or self._next_value(f"-{ch} (--{name})")))
            return


def _check_output(output: str, *, verb: str, outputs: list[str]) -> None:
    """Step 5: an exact entry, or the prefix of an entry ending in `=*`."""
    for allowed in outputs:
        if allowed.endswith("=*"):
            if output.startswith(allowed[:-1]):
                return
        elif output == allowed:
            return
    raise _Rejected(
        "output-not-allowed",
        f"-o {output} is not allowed for {verb}; allowed: {', '.join(outputs) or 'none'}",
    )


def _check_sensitive(positionals: list[str], *, output: str | None, cli_block: dict) -> None:
    """Step 6: each comma-separated part of the first positional, `/name`
    and `.group` stripped and lower-cased (`Secret`, `secret/s1`,
    `secrets.v1`, `secret,pods` all resolve to a plain `secret`/`secrets`),
    against `sensitiveTypes` -- then only `sensitiveOutputs` (or no `-o` at
    all) may be asked for."""
    sensitive_outputs = cli_block.get("sensitiveOutputs") or []
    if not positionals or output is None or output in sensitive_outputs:
        return
    sensitive = {t.lower() for t in cli_block.get("sensitiveTypes") or []}
    for part in positionals[0].split(","):
        kind = resource_type(part)
        if kind in sensitive:
            allowed = ["the default table", *(f"-o {o}" for o in sensitive_outputs)]
            shown = f"{', '.join(allowed[:-1])} or {allowed[-1]}" if len(allowed) > 1 else allowed[0]
            raise _Rejected("sensitive-type", f"{kind} is sensitive: only {shown} are allowed")


def resource_type(part: str) -> str:
    """One comma-separated part of a `get` positional as a bare, lower-cased
    resource type: `/name` and `.group` stripped, so `Secret`, `secret/s1` and
    `secrets.v1` resolve to `secret`/`secrets`."""
    return part.split("/", 1)[0].lower().split(".", 1)[0]


def require_allowed(argv: list[str], cli_block: dict | None = None) -> None:
    """Raises `ValueError(f"{reason}: {hint}")` unless `argv` (no leading
    `kubectl`) passes `validate()`. For callers that build their own argv
    and exec it themselves, rather than the normalised one `validate()`
    returns -- the `export` and `logs` tasks."""
    cli_block = cli_block if cli_block is not None else packbuild.load_pack_yaml()["cli"]
    validation = validate(argv, cli_block)
    if not validation.ok:
        raise ValueError(f"{validation.rejection.reason}: {validation.rejection.hint}")


def _apply_logs_defaults(flags: list[_Flag], *, limit: int) -> list[str]:
    """Step 8, `logs` only: clamp `--limit-bytes` in place; return the
    defaults to append (`--tail=200` with no tail/since window, and
    `--limit-bytes` when not given)."""
    defaults: list[str] = []
    if not any(f.name in _LOGS_WINDOW_FLAGS for f in flags):
        defaults.append(_LOGS_DEFAULT_TAIL)
    has_limit = False
    for f in flags:
        if f.name != _LIMIT_BYTES_FLAG:
            continue
        # kubectl reads 0 as "no limit", so a value must be a positive integer.
        if f.value is None or not _INTEGER_RE.fullmatch(f.value) or int(f.value) < 1:
            raise _Rejected("bad-value", f"--{_LIMIT_BYTES_FLAG} must be a positive integer, not '{f.value}'")
        f.value = str(min(int(f.value), limit))
        has_limit = True
    if not has_limit:
        defaults.append(f"--{_LIMIT_BYTES_FLAG}={limit}")
    return defaults


def _render(flag: _Flag) -> str:
    """Step 9: `--name=value`, or bare `--name` for a boolean given without `=`."""
    return f"--{flag.name}" if flag.value is None else f"--{flag.name}={flag.value}"


def full_output_for(argv: list[str], *, cluster_name: str | None) -> dict | None:
    """`{"task": "export"|"logs", "inputs": {...}}`: the queued task that
    returns the whole output of the `get` or `logs` command whose normalised
    `argv` (as `validate()` returns it) was cut short, with the inputs to
    give it -- or `None` when no queued task can stand in for the command.

    Never a hint that would fail or narrow what was asked. `None` when the
    task cannot say what the command meant (`get` with neither `--namespace`
    nor `--all-namespaces` reads the kubeconfig's own default namespace;
    `logs` without `--namespace`), when it cannot do it at all (`logs
    --previous`, `--since-time`), or when it would refuse the inputs (the
    same builder the task runs, so Secrets, a bad name or `--since` such as
    `1.5h` come out `None`). Otherwise the task covers a superset: `get pods
    web-0` becomes every pod, `--output`, `--field-selector` and `--sort-by`
    are dropped (the export is always JSON), and so are `--grep`, `--tail`
    and the other `logs` flags the task sets itself; a `logs` command with no
    `--since` gets the task's own default window.

    `inputs` uses the task's own input names, holds only the ones the command
    supplied (plus `clusterName`, when given), and never a null."""
    if not argv or argv[0] not in (_GET_VERB, _LOGS_VERB):
        return None
    positionals, flags = _split_normalised(argv[1:])
    if argv[0] == _GET_VERB:
        task, inputs = "export", _export_inputs(positionals, flags)
    else:
        task, inputs = "logs", _logs_inputs(positionals, flags)
    if inputs is None:
        return None
    if cluster_name:
        inputs = {"clusterName": cluster_name, **inputs}
    return {"task": task, "inputs": inputs}


def _split_normalised(tokens: list[str]) -> tuple[list[str], list[_Flag]]:
    """The tokens after the verb of a normalised argv: every flag is
    `--name[=value]`, so anything not starting with `--` is a positional."""
    positionals: list[str] = []
    flags: list[_Flag] = []
    for token in tokens:
        if token.startswith("--"):
            name, has_equals, value = token[2:].partition("=")
            flags.append(_Flag(name, value if has_equals else None))
        else:
            positionals.append(token)
    return positionals, flags


def _last_value(flags: list[_Flag], name: str) -> str | None:
    """A value flag's final value (kubectl keeps the last occurrence), `None`
    when it is absent or empty -- kubectl reads an empty value as unset."""
    value = None
    for flag in flags:
        if flag.name == name:
            value = flag.value
    return value or None


def _is_set(flags: list[_Flag], name: str) -> bool:
    """A boolean flag's final state: bare or `=true` is set, `=false` is not;
    the last occurrence wins."""
    state = False
    for flag in flags:
        if flag.name == name:
            state = flag.value != "false"
    return state


def _export_inputs(positionals: list[str], flags: list[_Flag]) -> dict[str, str] | None:
    """The `export` task's inputs (minus `clusterName`) for a normalised `get`."""
    # Imported here: export.py imports this module.
    from .export import build_export_argv

    resources = _export_resources(positionals)
    if resources is None:
        return None
    inputs = {"resources": resources}
    if not _is_set(flags, "all-namespaces"):
        namespace = _last_value(flags, "namespace")
        if namespace is None:
            return None
        inputs["namespace"] = namespace
    selector = _last_value(flags, "selector")
    if selector:
        inputs["selector"] = selector
    try:
        build_export_argv(inputs["resources"], inputs.get("namespace"), inputs.get("selector"))
    except ValueError:
        return None
    return inputs


def _export_resources(positionals: list[str]) -> str | None:
    """`get`'s positionals as the export's comma list of resource types:
    `pods`, `pods,svc` and `pods/a` as given; `pods a b` (a type, then names)
    as the type; `pods/a svc/b pods/c` as `pods,svc`. Always a superset."""
    if not positionals:
        return None
    first, *rest = positionals
    if not rest or "/" not in first:
        return first
    kinds: list[str] = []
    for positional in positionals:
        kind, slash, _name = positional.partition("/")
        if not slash:
            return None  # kubectl refuses a bare name beside type/name arguments
        if kind not in kinds:
            kinds.append(kind)
    return ",".join(kinds)


def _logs_inputs(positionals: list[str], flags: list[_Flag]) -> dict[str, str] | None:
    """The `logs` task's inputs (minus `clusterName`) for a normalised `logs`."""
    # Imported here: logs.py imports this module.
    from .logs import DEFAULT_SINCE, build_logs_argv

    namespace = _last_value(flags, "namespace")
    if namespace is None or len(positionals) > 2 or _is_set(flags, "previous"):
        return None
    if any(flag.name == "since-time" for flag in flags):
        return None
    inputs = {"namespace": namespace}
    selector = _last_value(flags, "selector")
    if selector:
        inputs["selector"] = selector
    if positionals:
        inputs["workload"] = positionals[0]
    since = _last_value(flags, "since")
    if since:
        inputs["since"] = since
    # `logs POD CONTAINER`; an explicit --container wins over the positional.
    container = _last_value(flags, "container") or (positionals[1] if len(positionals) == 2 else None)
    if container and not _is_set(flags, "all-containers"):
        inputs["container"] = container
    try:
        # Also refuses a selector together with a workload, and neither.
        build_logs_argv(
            namespace,
            selector=inputs.get("selector"),
            workload=inputs.get("workload"),
            container=inputs.get("container"),
            since=inputs.get("since", DEFAULT_SINCE),
        )
    except ValueError:
        return None
    return inputs


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
    cluster_name: str | None = None,
) -> dict:
    """Platform-contract §7's executor -- `rw.cli_result.v2`. Re-validates
    `argv` from scratch against the pack's own `cli` block, regardless of
    what papi already checked (the edge is authoritative): a rejected
    `argv` returns here with `exitCode: -1` and never reaches `subprocess`.
    An accepted one is never exec'd as given -- only the normalised argv
    `validate()` produced runs, after this executor's own `--kubeconfig`
    and `--request-timeout`.

    A `truncated` result of a `get` or `logs` also carries `fullOutput`, the
    queued task that returns all of it (`full_output_for()`); `cluster_name`
    is the `clusterName` that hint passes along, left out when not given.
    `fullOutput` is `None` in every other case, and always present.

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
            "fullOutput": None,
        }

    effective_timeout = resolve_timeout_seconds(timeout_seconds, cli_block["output"])

    with kubeconfig_file(kubeconfig_yaml, workdir) as kubeconfig_path:
        env = scrubbed_env(kubeconfig_path)
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
            "fullOutput": full_output_for(validation.argv, cluster_name=cluster_name) if truncated else None,
        }
