"""Daily/weekly artifact rendering and safe atomic writes."""

from __future__ import annotations

import os
import tempfile
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Sequence

from .context import generate_context_with_optional_summarizer, generate_important_context
from .schema import NormalizedEvent, parse_datetime


def atomic_write(path: Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".life-iq-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _status_to_dict(status: Any) -> Mapping[str, Any]:
    if hasattr(status, "to_dict"):
        return status.to_dict()
    if isinstance(status, Mapping):
        return status
    return {"source": "unknown", "status": "unknown", "diagnostic": ""}


def render_daily(
    day: date,
    events: Sequence[NormalizedEvent],
    source_statuses: Sequence[Any] = (),
    *,
    generated_at: Optional[datetime] = None,
) -> str:
    ordered = sorted(events, key=lambda event: (event.occurred_at, event.event_id))
    grouped = defaultdict(list)
    for event in ordered:
        grouped[event.event_type].append(event)
    lines = ["# Life IQ 日次ログ %s" % day.isoformat(), "", "## その日の流れ"]
    if ordered:
        for event in ordered:
            lines.append("- %s `%s` [%s] %s (重要度 %.0f, 確信度 %.0f%%)" % (
                event.occurred_at.strftime("%H:%M"), event.event_type, event.source, event.summary, event.importance, event.confidence * 100,
            ))
    else:
        lines.append("- 新しいイベントはありません（取得状態は下記を参照）。")
    lines.extend(["", "## 新規・更新イベント"])
    if grouped:
        for event_type in sorted(grouped):
            lines.append("### %s" % event_type)
            for event in grouped[event_type]:
                entities = ", ".join(event.entities[:5])
                lines.append("- %s%s" % (event.summary, "（" + entities + "）" if entities else ""))
    else:
        lines.append("- なし")
    lines.extend(["", "## 未完了事項"])
    unfinished = [event for event in ordered if event.status.lower() in ("open", "pending", "todo", "unresolved", "in_progress") or event.event_type in ("task", "commitment", "deadline")]
    lines.extend(["- %s [%s]" % (event.summary, event.source) for event in unfinished] or ["- 記録なし"])
    lines.extend(["", "## 情報源と取得状態"])
    for status in source_statuses:
        item = _status_to_dict(status)
        diagnostic = str(item.get("diagnostic", ""))[:300]
        lines.append("- %s: %s%s" % (item.get("source", "unknown"), item.get("status", "unknown"), " — " + diagnostic if diagnostic else ""))
    if not source_statuses:
        lines.append("- 取得状態は未報告です。")
    lines.extend(["", "生成時刻: %s" % parse_datetime(generated_at or datetime.now(timezone.utc)).isoformat()])
    return "\n".join(lines).strip() + "\n"


def render_weekly(week_start: date, events: Sequence[NormalizedEvent], *, generated_at: Optional[datetime] = None) -> str:
    week_end = week_start + timedelta(days=6)
    ordered = sorted(events, key=lambda event: (-event.importance, -event.occurred_at.timestamp(), event.event_id))
    lines = ["# Life IQ 週次サマリー %s〜%s" % (week_start.isoformat(), week_end.isoformat()), "", "## 今週の重要事項"]
    lines.extend(["- [%d] %s [%s] %s" % (round(event.importance), event.event_type, event.source, event.summary) for event in ordered[:30]] or ["- 記録なし"])
    lines.extend(["", "## 未完了事項"])
    unfinished = [event for event in ordered if event.status.lower() in ("open", "pending", "todo", "unresolved", "in_progress") or event.event_type in ("task", "commitment", "deadline")]
    lines.extend(["- %s" % event.summary for event in unfinished[:20]] or ["- 記録なし"])
    lines.extend(["", "生成時刻: %s" % parse_datetime(generated_at or datetime.now(timezone.utc)).isoformat()])
    return "\n".join(lines).strip() + "\n"


class ArtifactWriter:
    def __init__(self, root: Path, *, context_path: Optional[Path] = None, drive_sync_path: Optional[Path] = None, sync_outputs: bool = True) -> None:
        self.root = Path(root)
        self.knowledge = self.root / "knowledge"
        self.context_path = Path(context_path) if context_path else self.root / "IMPORTANT_CONTEXT.md"
        self.drive_sync_path = Path(drive_sync_path) if drive_sync_path else None
        self.sync_outputs = bool(sync_outputs)

    def _mirror(self, relative: str, text: str) -> Optional[Path]:
        if not self.sync_outputs or self.drive_sync_path is None:
            return None
        # A missing Drive mount is normal; keeping the local artifact is the
        # safe behavior and lets the next run retry synchronization.
        if not self.drive_sync_path.exists() or not self.drive_sync_path.is_dir():
            return None
        destination = self.drive_sync_path / relative
        atomic_write(destination, text)
        return destination

    def write_daily(self, day: date, events: Sequence[NormalizedEvent], statuses: Sequence[Any], *, generated_at: Optional[datetime] = None) -> Path:
        text = render_daily(day, events, statuses, generated_at=generated_at)
        relative = "knowledge/daily/%s.md" % day.isoformat()
        destination = self.root / relative
        atomic_write(destination, text)
        self._mirror(relative, text)
        return destination

    def write_weekly(self, week_start: date, events: Sequence[NormalizedEvent], *, generated_at: Optional[datetime] = None) -> Path:
        text = render_weekly(week_start, events, generated_at=generated_at)
        relative = "knowledge/summaries/weekly/%s.md" % week_start.strftime("%G-W%V")
        destination = self.root / relative
        atomic_write(destination, text)
        self._mirror(relative, text)
        return destination

    def write_context(self, events: Sequence[NormalizedEvent], statuses: Sequence[Any], *, generated_at: Optional[datetime] = None, summarizer_command: Optional[str] = None) -> Path:
        text = generate_context_with_optional_summarizer(
            events,
            statuses,
            generated_at=generated_at,
            summarizer_command=summarizer_command,
        )
        atomic_write(self.context_path, text)
        try:
            relative = str(self.context_path.relative_to(self.root))
        except ValueError:
            relative = "IMPORTANT_CONTEXT.md"
        self._mirror(relative, text)
        return self.context_path
