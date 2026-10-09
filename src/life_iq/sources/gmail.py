# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Gmail read-only adapter.

The MVP accepts a local JSON export or an injected record list.  OAuth setup
is documented in README; no access token is read by this module.  This keeps a
scheduled job useful on a machine where the interactive OAuth flow has not
yet been completed.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional

from .base import AdapterResult, SourceStatus, SourceWindow, in_window, make_event, read_json_records, stable_ref
from ..privacy import redact_text


def _timestamp(record: Mapping[str, Any]) -> Any:
    for key in ("occurred_at", "received_at", "internalDate", "timestamp", "date", "updated_at"):
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def classify_gmail_event(subject: str, body: str = "") -> str:
    text = (subject + " " + body).lower()
    if any(word in text for word in ("refund", "返金")):
        return "refund"
    if any(word in text for word in ("return", "返品")):
        return "return"
    if any(word in text for word in ("delivered", "delivery", "配達", "配送")):
        return "delivery"
    if any(word in text for word in ("order", "注文", "購入")) and any(word in text for word in ("amazon", "楽天", "rakuten")):
        return "purchase"
    if any(word in text for word in ("deadline", "期限", "due", "締切")):
        return "deadline"
    if any(word in text for word in ("meeting", "calendar", "会議", "予定")):
        return "schedule"
    if any(word in text for word in ("todo", "task", "action required", "対応")):
        return "task"
    return "observation"


class GmailAdapter:
    source = "gmail"

    def __init__(self, path: Optional[Path] = None, records: Optional[Iterable[Mapping[str, Any]]] = None) -> None:
        self.path = Path(path) if path else None
        self.records = list(records) if records is not None else None

    def collect(self, window: SourceWindow, cursor: Optional[str] = None) -> AdapterResult:
        if self.records is None:
            records, diagnostic = read_json_records(self.path)
            if self.path is None:
                return AdapterResult(status=SourceStatus(self.source, "needs_setup", "Gmail read-only OAuth/export is not configured"))
            if not self.path.exists():
                return AdapterResult(status=SourceStatus(self.source, "needs_setup", "Gmail export is unavailable; complete read-only OAuth setup"))
            if diagnostic and not records:
                return AdapterResult(status=SourceStatus(self.source, "failed", diagnostic))
        else:
            records = self.records
            diagnostic = None

        events = []
        latest = cursor
        for record in records:
            timestamp = _timestamp(record)
            if timestamp is None or not in_window(timestamp, window):
                continue
            try:
                parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")) if isinstance(timestamp, str) else None
                if parsed is not None:
                    latest = max(latest or "", parsed.isoformat())
            except ValueError:
                pass
            message_id = record.get("id") or record.get("message_id") or record.get("thread_id")
            subject = redact_text(record.get("subject") or record.get("title") or "(件名なし)", max_chars=180)
            # Snippets are sufficient for event classification; full bodies are
            # never placed in metadata or artifacts.
            snippet = redact_text(record.get("snippet") or record.get("text") or record.get("body") or "", max_chars=320)
            source_ref = str(message_id) if message_id else stable_ref("gmail", timestamp, subject)
            entities = record.get("entities") or []
            sender = record.get("from") or record.get("sender")
            if sender:
                entities = list(entities) + [sender]
            metadata = {
                "thread_id": str(record.get("thread_id")) if record.get("thread_id") else None,
                "labels": list(record.get("labels") or [])[:10],
                "order_reference": str(record.get("order_id"))[:80] if record.get("order_id") else None,
                "importance": record.get("importance", 0),
            }
            events.append(
                make_event(
                    source=self.source,
                    source_ref=source_ref,
                    timestamp=timestamp,
                    event_type=classify_gmail_event(subject, snippet),
                    summary_parts=(subject, snippet),
                    entities=entities,
                    confidence=0.86,
                    metadata=metadata,
                )
            )
        status_text = "read-only local export" if self.records is not None else "read-only local Gmail export"
        if diagnostic:
            status_text += "; " + diagnostic
        return AdapterResult(events=events, status=SourceStatus(self.source, "success", status_text, latest, len(events)))
