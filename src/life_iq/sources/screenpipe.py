# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Screenpipe capture adapter using local JSON/JSONL exports."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional
from pathlib import Path

from .base import AdapterResult, SourceStatus, SourceWindow, any_capture_flag, capture_receipt_status, explicit_capture_flag, in_window, make_event, read_json_records_with_fingerprint, stable_ref
from .line import is_excluded_line_conversation
from ..privacy import redact_text


def _timestamp(record: Mapping[str, Any]) -> Any:
    for key in ("occurred_at", "timestamp", "created_at", "start_time", "time"):
        if record.get(key) not in (None, ""):
            return record[key]
    return None


def _explicit_flag(value: Any) -> bool:
    return explicit_capture_flag(value)


def _any_flag(record: Mapping[str, Any], keys: Iterable[str]) -> bool:
    return any_capture_flag(record, keys)


def _service_marker(record: Mapping[str, Any]) -> str:
    values = [record.get(key) for key in ("app", "application", "site", "provider", "url", "page_url", "browser_url", "workspace_url", "team_url", "window")]
    text = " ".join(str(value or "").casefold() for value in values)
    if re.search(r"(?<![a-z0-9])slack(?![a-z0-9.-])", text):
        return "slack"
    if re.search(r"(?<![a-z0-9])discord(?![a-z0-9.-])", text):
        return "discord"
    if re.search(r"(?<![a-z0-9])line(?![a-z0-9.-])", text) or "ライン" in text:
        return "line"
    if re.search(r"(?<![a-z0-9])x\.com(?![a-z0-9.-])", text) or re.search(r"(?<![a-z0-9])twitter(?![a-z0-9.-])", text):
        return "x"
    return ""


def _scope_allowed(record: Mapping[str, Any]) -> bool:
    """Only retain explicitly bounded scope or a known local Life IQ view."""

    app = str(record.get("app") or record.get("application") or "").casefold()
    window = str(record.get("window") or "").casefold()
    if "life iq" in app or "life-iq" in app or "life iq" in window or "life-iq" in window:
        return True
    service = _service_marker(record)
    if service == "line":
        return not is_excluded_line_conversation(record)
    if service == "x":
        return (
            not _any_flag(record, ("general_timeline", "timeline"))
            and _any_flag(record, ("about_self", "is_relevant", "mentions_user", "notification_for_self", "target_is_self", "own_post", "author_is_self", "is_self", "self_authored"))
        )
    if service == "discord":
        return _any_flag(record, ("is_dm", "dm", "is_self", "author_is_self", "self_authored", "has_user_sent", "user_has_posted", "server_user_message_history"))
    if service == "slack":
        return _any_flag(record, ("is_dm", "dm", "is_member", "is_participant", "user_is_member", "joined", "participating", "user_has_posted", "has_user_sent", "user_sent_message", "user_sent_messages", "channel_user_sent", "channel_member"))
    return False


class ScreenpipeAdapter:
    source = "screenpipe"

    def __init__(self, path: Optional[Path] = None, records: Optional[Iterable[Mapping[str, Any]]] = None) -> None:
        self.path = Path(path) if path else None
        self.records = list(records) if records is not None else None

    def collect(self, window: SourceWindow, cursor: Optional[str] = None) -> AdapterResult:
        if self.records is None:
            if self.path is None:
                return AdapterResult(status=SourceStatus(self.source, "skipped", "Screenpipe capture is not configured"))
            records, diagnostic, capture_sha256, capture_bytes = read_json_records_with_fingerprint(self.path)
            fingerprint = (capture_sha256, capture_bytes) if capture_sha256 is not None else None
            receipt_status = capture_receipt_status(self.path, self.source, fingerprint=fingerprint)
            if receipt_status is not None:
                return AdapterResult(status=receipt_status)
            if diagnostic and not records:
                return AdapterResult(status=SourceStatus(self.source, "failed", diagnostic))
        else:
            records = self.records
            diagnostic = None
        events = []
        latest = cursor
        excluded = 0
        for record in records:
            if any_capture_flag(record, ("auto_traversed", "opened_unread", "adapter_action")):
                excluded += 1
                continue
            if not _scope_allowed(record):
                excluded += 1
                continue
            timestamp = _timestamp(record)
            if timestamp is None or not in_window(timestamp, window):
                continue
            text = record.get("text") or record.get("transcript") or record.get("ocr_text") or record.get("content") or ""
            app = record.get("app") or record.get("application") or record.get("window") or "unknown app"
            text = redact_text(text, max_chars=360)
            if not text:
                continue
            ref = record.get("frame_id") or record.get("audio_chunk_id") or record.get("id") or stable_ref("screenpipe", timestamp, app, text)
            entities = record.get("entities") or []
            events.append(
                make_event(
                    source=self.source,
                    source_ref=str(ref),
                    timestamp=timestamp,
                    event_type="conversation" if record.get("audio_chunk_id") or record.get("transcript") else "activity",
                    summary_parts=(str(app), text),
                    entities=entities,
                    confidence=0.63,
                    metadata={"app": str(app)[:100], "window": str(record.get("window", ""))[:120]},
                )
            )
            latest = str(timestamp)
        message = "read-only local capture; excluded=%d" % excluded
        if diagnostic:
            message += "; " + diagnostic
        return AdapterResult(events=events, status=SourceStatus(self.source, "success", message, latest, len(events)))
