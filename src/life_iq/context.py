"""Rolling IMPORTANT_CONTEXT generation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import shlex
import subprocess
from typing import Any, Iterable, Mapping, Optional, Sequence

from .privacy import redact_mapping, redact_text, sensitivity_for
from .schema import NormalizedEvent, parse_datetime


def _status_line(status: Any) -> str:
    if hasattr(status, "source"):
        source = str(status.source)
        state = str(status.status)
        diagnostic = str(getattr(status, "diagnostic", ""))[:180]
    elif isinstance(status, Mapping):
        source = str(status.get("source", "unknown"))
        state = str(status.get("status", "unknown"))
        diagnostic = str(status.get("diagnostic", ""))[:180]
    else:
        return "- 不明な入力状態"
    suffix = " — " + diagnostic if diagnostic else ""
    return "- %s: %s%s" % (source, state, suffix)


def _event_line(event: NormalizedEvent) -> str:
    when = event.occurred_at.astimezone(timezone.utc).strftime("%m-%d %H:%M UTC")
    entities = " / ".join(event.entities[:4])
    entity_text = "（%s）" % entities if entities else ""
    return "- [%d] %s — %s%s [%s]" % (round(event.importance), when, event.summary, entity_text, event.source)


def generate_important_context(
    events: Iterable[NormalizedEvent],
    source_statuses: Sequence[Any] = (),
    *,
    generated_at: Optional[datetime] = None,
    max_chars: int = 4000,
) -> str:
    """Render a bounded, decision-oriented context file.

    The function is deterministic when ``generated_at`` is provided.  It does
    not claim a missing source had no activity; its status is shown explicitly.
    """

    generated = parse_datetime(generated_at or datetime.now(timezone.utc))
    ordered = sorted(list(events), key=lambda event: (-event.importance, -event.occurred_at.timestamp(), event.event_id))
    open_events = [event for event in ordered if event.status.lower() in ("open", "pending", "todo", "unresolved", "in_progress") or event.event_type in ("task", "commitment", "deadline")]
    planned = [event for event in ordered if event.event_type in ("deadline", "appointment", "schedule")]
    projects = [event for event in ordered if event.event_type in ("project", "file_created", "file_updated")]
    relationships = [event for event in ordered if event.event_type in ("relationship", "conversation")]
    patterns = [event for event in ordered if event.event_type == "pattern"]

    lines = [
        "# IMPORTANT_CONTEXT",
        "",
        "このファイルは次回の意思決定に必要な直近の文脈だけを保持します。原文・認証情報は保存しません。",
        "",
        "## 現在の重点",
    ]
    focus = ordered[:5]
    lines.extend([_event_line(event) for event in focus] or ["- 直近の新規イベントはありません。"])
    lines.extend(["", "## 期限と約束"])
    lines.extend([_event_line(event) for event in planned[:6]] or ["- 記録された期限・予定はありません。"])
    lines.extend(["", "## 保留事項"])
    lines.extend([_event_line(event) for event in open_events[:8]] or ["- 記録された保留事項はありません。"])
    lines.extend(["", "## 関係する人物・プロジェクト"])
    lines.extend([_event_line(event) for event in (relationships[:4] + projects[:4])[:8]] or ["- 直近の関連情報はありません。"])
    lines.extend(["", "## 直近の生活パターン"])
    lines.extend([_event_line(event) for event in patterns[:5]] or ["- 反復パターンはまだ判定していません。"])
    lines.extend(["", "## データ取得状態"])
    lines.extend([_status_line(status) for status in source_statuses] or ["- 取得状態は未報告です。"])
    lines.extend(["", "最終更新: %s" % generated.isoformat()])

    text = "\n".join(lines).strip() + "\n"
    if len(text) <= max_chars:
        return text

    # Keep headings and high-priority lines while trimming long summaries.
    clipped = []
    for line in text.splitlines():
        if len("\n".join(clipped)) + len(line) + 1 <= max_chars:
            clipped.append(line)
        elif line.startswith("- "):
            remaining = max_chars - len("\n".join(clipped)) - 5
            if remaining > 24:
                clipped.append(line[:remaining].rstrip() + "…")
            break
    return "\n".join(clipped).rstrip() + "\n"


def build_context(*args: Any, **kwargs: Any) -> str:
    return generate_important_context(*args, **kwargs)


def generate_context_with_optional_summarizer(
    events: Iterable[NormalizedEvent],
    source_statuses: Sequence[Any] = (),
    *,
    generated_at: Optional[datetime] = None,
    max_chars: int = 4000,
    summarizer_command: Optional[str] = None,
) -> str:
    """Use an explicitly configured local summarizer, with a safe fallback.

    The command receives only normalized, already-redacted JSON on stdin and
    must return Markdown on stdout.  ``shell=False``, a short timeout, a
    minimal environment, and output redaction keep this hook low-risk.  Any
    non-zero exit, timeout, oversized/empty output, or high-risk output falls
    back to :func:`generate_important_context`.
    """

    event_list = list(events)
    fallback = generate_important_context(event_list, source_statuses, generated_at=generated_at, max_chars=max_chars)
    if not summarizer_command or not str(summarizer_command).strip():
        return fallback
    try:
        argv = shlex.split(str(summarizer_command))
    except ValueError:
        return fallback
    if not argv:
        return fallback
    statuses = []
    for status in source_statuses:
        if hasattr(status, "to_dict"):
            statuses.append(status.to_dict())
        elif isinstance(status, Mapping):
            statuses.append(dict(status))
    payload = {
        "instruction": "Return a short Japanese rolling context in Markdown. Do not include credentials or raw source bodies.",
        "events": [redact_mapping(event.to_dict()) for event in event_list],
        "source_statuses": statuses,
    }
    minimal_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
    try:
        completed = subprocess.run(
            argv,
            input=json.dumps(payload, ensure_ascii=False, sort_keys=True),
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
            shell=False,
            env=minimal_env,
        )
    except (OSError, subprocess.SubprocessError):
        return fallback
    if completed.returncode != 0 or not completed.stdout.strip():
        return fallback
    output = redact_text(completed.stdout, max_chars=max_chars)
    if not output or sensitivity_for(output) == "restricted" or "IMPORTANT_CONTEXT" not in output:
        return fallback
    return output.rstrip() + "\n"
