"""A readable text rendering of a sanitized object plus its events --
`inspect`'s `describe` mode (platform-contract §5). This is built from the
object and its events directly, never by shelling out to `kubectl
describe`: the capability has no shell access to begin with, and building
it here means it goes through the same sanitizer as `get` (`sanitize.py`)
-- there is no side door for a Secret's data to leak through a text dump.

Deliberately plain, not a `kubectl describe` clone: enough structure for an
agent (or a person) to read at a glance -- identity, labels/annotations,
spec highlights already summarised by `k8sSummary`-shaped facts, status
conditions, and recent events -- without reimplementing `kubectl`'s much
larger per-kind describer set.
"""

from __future__ import annotations

_EVENT_LIMIT = 20


def _format_labels(labels: dict) -> str:
    if not labels:
        return "<none>"
    return ", ".join(f"{k}={v}" for k, v in sorted(labels.items()))


def _format_conditions(status: dict | None) -> list[str]:
    conditions = (status or {}).get("conditions") or []
    lines = []
    for condition in conditions:
        lines.append(
            f"  {condition.get('type', '?')}: {condition.get('status', '?')}"
            f" (reason={condition.get('reason', '-')}, message={condition.get('message', '-')})"
        )
    return lines


def _format_events(events: list[dict]) -> list[str]:
    if not events:
        return ["  <none>"]
    lines = []
    for event in events[:_EVENT_LIMIT]:
        when = event.get("lastTimestamp") or event.get("eventTime") or "?"
        lines.append(f"  [{event.get('type', '?')}] {when} {event.get('reason', '?')}: {event.get('message', '')}")
    if len(events) > _EVENT_LIMIT:
        lines.append(f"  ... and {len(events) - _EVENT_LIMIT} more")
    return lines


def render(document: dict, status: dict | None, events: list[dict], path: str) -> str:
    metadata = document.get("metadata") or {}
    lines = [
        f"Path:        {path}",
        f"Kind:        {document.get('kind', '?')}",
        f"Name:        {metadata.get('name', '?')}",
        f"Namespace:   {metadata.get('namespace', '<cluster-scoped>')}",
        f"Created:     {metadata.get('creationTimestamp', '?')}",
        f"Labels:      {_format_labels(metadata.get('labels') or {})}",
        f"Annotations: {_format_labels(metadata.get('annotations') or {})}",
        "",
        "Spec:",
        f"  {document.get('spec', {})}",
        "",
        "Status conditions:",
    ]
    condition_lines = _format_conditions(status)
    lines.extend(condition_lines or ["  <none>"])
    lines.append("")
    lines.append("Recent events:")
    lines.extend(_format_events(events))
    return "\n".join(lines)
