# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Local send-intent materialization with no external sender.

An intent is a human re-checkable payload, not a transport job.  Creating or
listing one never opens an app, changes read state, clicks a send button, or
contacts LINE, Slack, Discord, or X.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .privacy import redact_mapping, redact_text
from .replies import QueueTransitionError, ReplyCandidate, ReplyQueue


SENDABLE_SOURCES = frozenset(("line", "slack", "discord"))


class SendIntentError(QueueTransitionError):
    """Raised when a candidate cannot be materialized as a local intent."""


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".send-intent-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


@dataclass(frozen=True)
class SendIntent:
    intent_id: str
    candidate_id: str
    source: str
    recipient: str
    summary: str
    body: str
    route: Mapping[str, Any]
    status: str
    path: Path
    materialized_at: str
    risk_flags: tuple = ()
    thread_info: Mapping[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "candidate_id": self.candidate_id,
            "source": self.source,
            "recipient": self.recipient,
            "summary": self.summary,
            "body": self.body,
            "route": dict(self.route),
            "status": self.status,
            "path": str(self.path),
            "materialized_at": self.materialized_at,
            "risk_flags": list(self.risk_flags),
            "thread_info": dict(self.thread_info or {}),
            "ui_confirmation_required": True,
            "external_send_enabled": False,
        }


def _intent_payload(candidate: ReplyCandidate, *, materialized_at: datetime) -> Dict[str, Any]:
    if candidate.source not in SENDABLE_SOURCES:
        raise SendIntentError("source cannot create send intent: %s" % candidate.source)
    if not candidate.send_ready or candidate.status != "approved":
        raise SendIntentError("only approved, non-blocked candidates can create send intents")
    return {
        "version": 1,
        "intent_id": candidate.candidate_id,
        "candidate_id": candidate.candidate_id,
        "source": candidate.source,
        "recipient": redact_text(candidate.recipient, max_chars=220),
        "summary": redact_text(candidate.original_summary, max_chars=600),
        "original_summary": redact_text(candidate.original_summary, max_chars=600),
        "body": redact_text(candidate.proposed_reply, max_chars=900),
        "route": redact_mapping(dict(candidate.route)),
        "thread_info": redact_mapping(dict(candidate.thread_info)),
        "risk_flags": list(candidate.risk_flags),
        "status": "send-ready",
        "materialized_at": materialized_at.isoformat(),
        "ui_confirmation_required": True,
        "external_send_enabled": False,
        "send_executed_by_life_iq": False,
    }


def _from_payload(payload: Mapping[str, Any], path: Path) -> SendIntent:
    return SendIntent(
        intent_id=str(payload.get("intent_id") or payload.get("candidate_id") or ""),
        candidate_id=str(payload.get("candidate_id") or ""),
        source=str(payload.get("source") or ""),
        recipient=redact_text(payload.get("recipient"), max_chars=220),
        summary=redact_text(payload.get("summary") or payload.get("original_summary"), max_chars=600),
        body=redact_text(payload.get("body"), max_chars=900),
        route=redact_mapping(dict(payload.get("route") or {})),
        status=str(payload.get("status") or ""),
        path=path,
        materialized_at=str(payload.get("materialized_at") or ""),
        risk_flags=tuple(str(item) for item in (payload.get("risk_flags") or ())),
        thread_info=redact_mapping(dict(payload.get("thread_info") or {})),
    )


def materialize_send_intent(
    queue: ReplyQueue,
    candidate_id: str,
    *,
    intent_dir: Optional[Path] = None,
    materialized_at: Optional[Any] = None,
) -> SendIntent:
    """Write an approved candidate to one atomic local send-intent JSON."""

    candidate = queue.get(candidate_id)
    if candidate.source not in SENDABLE_SOURCES:
        raise SendIntentError("source cannot create send intent: %s" % candidate.source)
    # This performs the queue's approval/send-ready checks without invoking a
    # sender.  Keep it before any filesystem mutation.
    try:
        queue.send_ready(candidate.candidate_id)
    except QueueTransitionError as exc:
        raise SendIntentError(str(exc))
    when = materialized_at
    if when is None:
        when = datetime.now(timezone.utc)
    when = when if isinstance(when, datetime) else datetime.fromisoformat(str(when).replace("Z", "+00:00"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    path = (Path(intent_dir) if intent_dir else queue.send_intents_path) / (queue.send_intent_path(candidate.candidate_id).name)
    payload = _intent_payload(candidate, materialized_at=when.astimezone(timezone.utc))
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SendIntentError("cannot read existing send intent: %s" % type(exc).__name__)
        if not isinstance(existing, Mapping):
            raise SendIntentError("existing send intent has invalid shape")
        comparable = ("candidate_id", "source", "recipient", "summary", "body", "route", "thread_info", "risk_flags")
        if any(existing.get(key) != payload.get(key) for key in comparable):
            raise SendIntentError("existing send intent differs; re-review required")
        return _from_payload(existing, path)
    _atomic_write(path, payload)
    return _from_payload(payload, path)


create_send_intent = materialize_send_intent
prepare_send_intent = materialize_send_intent


def list_send_intents(intent_dir: Path) -> List[SendIntent]:
    path = Path(intent_dir)
    if not path.exists():
        return []
    result: List[SendIntent] = []
    for item in sorted(path.glob("*.json")):
        try:
            value = json.loads(item.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(value, Mapping):
            result.append(_from_payload(value, item))
    return result


__all__ = [
    "SENDABLE_SOURCES",
    "SendIntent",
    "SendIntentError",
    "create_send_intent",
    "list_send_intents",
    "materialize_send_intent",
    "prepare_send_intent",
]
