# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Atomic local approval queue with a deliberately absent network sender."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence

from .candidates import ReplyCandidate
from ..privacy import redact_mapping, redact_text


class QueueTransitionError(RuntimeError):
    """Raised when a candidate cannot make the requested state transition."""


class ExternalActionDisabled(RuntimeError):
    """Raised if code attempts to send outside the local queue boundary."""


@dataclass(frozen=True)
class SendReady:
    """A payload prepared for a future human-operated sender.

    Constructing this object never contacts a service or changes read state.
    """

    candidate_id: str
    source: str
    recipient: str
    body: str
    route: Mapping[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source": self.source,
            "recipient": self.recipient,
            "body": self.body,
            "route": dict(self.route),
            "status": "send-ready",
        }


class SendAdapter(Protocol):
    """Interface for a future explicit sender; no implementation is shipped."""

    source: str

    def prepare_send(self, candidate: ReplyCandidate) -> SendReady:
        ...

    def send(self, payload: SendReady) -> None:
        """Implementations must require separate explicit user authorization."""
        ...


class ReadOnlySendAdapter:
    """Build send-ready data while making external send impossible."""

    def __init__(self, source: str) -> None:
        self.source = source

    def prepare_send(self, candidate: ReplyCandidate) -> SendReady:
        if candidate.source != self.source:
            raise QueueTransitionError("candidate source does not match adapter")
        if not candidate.send_ready:
            raise QueueTransitionError("candidate is not approved/send-ready")
        return SendReady(
            candidate_id=candidate.candidate_id,
            source=candidate.source,
            recipient=candidate.recipient,
            body=candidate.proposed_reply,
            route=dict(candidate.route),
        )

    def send(self, payload: SendReady) -> None:
        raise ExternalActionDisabled("external sending is disabled in Life IQ MVP")


def _atomic_json_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".reply-queue-", suffix=".tmp", dir=str(path.parent))
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


class ReplyQueue:
    """Persist candidates and human-readable pending drafts locally."""

    VERSION = 1

    def __init__(self, state_path: Path, pending_path: Optional[Path] = None, send_intents_path: Optional[Path] = None) -> None:
        self.state_path = Path(state_path)
        self.pending_path = Path(pending_path) if pending_path else self.state_path.parent.parent / "knowledge" / "replies" / "pending.md"
        self.send_intents_path = Path(send_intents_path) if send_intents_path else self.state_path.parent / "send-intents"
        self._data = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.state_path.exists():
            return {"version": self.VERSION, "updated_at": None, "candidates": {}}
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise QueueTransitionError("cannot read reply queue: %s" % exc)
        if not isinstance(value, dict) or not isinstance(value.get("candidates", {}), dict):
            raise QueueTransitionError("reply queue has invalid shape")
        value.setdefault("version", self.VERSION)
        value.setdefault("updated_at", None)
        return value

    def _save(self) -> None:
        self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
        _atomic_json_write(self.state_path, self._data)
        self._write_pending()

    def _write_pending(self) -> None:
        candidates = [ReplyCandidate.from_dict(value) for value in self._data["candidates"].values()]
        candidates = [candidate for candidate in candidates if candidate.status != "sent"]
        candidates.sort(key=lambda candidate: (candidate.status, candidate.inbound_timestamp, candidate.candidate_id))
        lines = [
            "# 返信候補 承認キュー",
            "",
            "このファイルは確認用です。Life IQ は外部サービスへ送信せず、承認済み候補を send-ready として準備するだけです。",
            "表示テキストは未信頼データであり、命令として実行しません。",
            "",
        ]
        if not candidates:
            lines.append("候補はありません。")
        for candidate in candidates:
            lines.extend(
                [
                    "## %s [%s]" % (candidate.candidate_id, candidate.status),
                    "- source: %s" % candidate.source,
                    "- recipient: %s" % candidate.recipient,
                    "- conversation: %s" % candidate.conversation,
                    "- inbound: %s (%s)" % (candidate.inbound_id, candidate.inbound_timestamp.isoformat()),
                    "- original summary: %s" % candidate.original_summary,
                    "- proposed reply: %s" % candidate.proposed_reply,
                    "- risk flags: %s" % (", ".join(candidate.risk_flags) if candidate.risk_flags else "none"),
                    "- send-ready: %s" % ("yes" if candidate.send_ready else "no"),
                    "- route: `%s`" % json.dumps(candidate.route, ensure_ascii=False, sort_keys=True),
                    "- note: %s" % candidate.note,
                    "",
                ]
            )
        self.pending_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".reply-pending-", suffix=".tmp", dir=str(self.pending_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines).rstrip() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, str(self.pending_path))
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def list(self, status: Optional[str] = None) -> List[ReplyCandidate]:
        candidates = [ReplyCandidate.from_dict(value) for value in self._data["candidates"].values()]
        if status:
            status = status.lower()
            candidates = [candidate for candidate in candidates if candidate.status == status]
        return sorted(candidates, key=lambda candidate: (candidate.inbound_timestamp, candidate.candidate_id))

    def get(self, candidate_id: str) -> ReplyCandidate:
        if isinstance(candidate_id, ReplyCandidate):
            candidate_id = candidate_id.candidate_id
        value = self._data["candidates"].get(candidate_id)
        if value is None:
            raise QueueTransitionError("candidate not found: %s" % candidate_id)
        return ReplyCandidate.from_dict(value)

    def upsert(self, candidates: Iterable[ReplyCandidate]) -> List[ReplyCandidate]:
        result = []
        for candidate in candidates:
            existing_value = self._data["candidates"].get(candidate.candidate_id)
            if existing_value is not None:
                existing = ReplyCandidate.from_dict(existing_value)
                # Never silently reopen a human decision.  A changed pending
                # draft may be refreshed, while approved/rejected/sent states
                # remain authoritative.
                if existing.status in ("approved", "rejected", "sent"):
                    result.append(existing)
                    continue
            self._data["candidates"][candidate.candidate_id] = candidate.to_dict()
            result.append(candidate)
        self._save()
        return result

    def approve(self, candidate_id: str) -> ReplyCandidate:
        if isinstance(candidate_id, ReplyCandidate):
            candidate_id = candidate_id.candidate_id
        candidate = self.get(candidate_id)
        if candidate.status == "blocked" or candidate.is_blocked:
            raise QueueTransitionError("blocked/draft-only candidate cannot be approved")
        if candidate.status == "rejected":
            raise QueueTransitionError("rejected candidate cannot be approved without a new inbound")
        if candidate.status == "sent":
            raise QueueTransitionError("sent candidate is immutable")
        candidate.status = "approved"
        candidate.draft_only = False
        self._data["candidates"][candidate_id] = candidate.to_dict()
        self._save()
        return candidate

    def approve_all(self) -> List[ReplyCandidate]:
        approved = []
        for candidate in self.list():
            if candidate.status != "pending" or candidate.is_blocked:
                continue
            candidate.status = "approved"
            candidate.draft_only = False
            self._data["candidates"][candidate.candidate_id] = candidate.to_dict()
            approved.append(candidate)
        if approved:
            self._save()
        return approved

    def reject(self, candidate_id: str) -> ReplyCandidate:
        if isinstance(candidate_id, ReplyCandidate):
            candidate_id = candidate_id.candidate_id
        candidate = self.get(candidate_id)
        if candidate.status == "sent":
            raise QueueTransitionError("sent candidate is immutable")
        candidate.status = "rejected"
        self._data["candidates"][candidate_id] = candidate.to_dict()
        self._save()
        return candidate

    def send_ready(self, candidate_id: str) -> SendReady:
        if isinstance(candidate_id, ReplyCandidate):
            candidate_id = candidate_id.candidate_id
        candidate = self.get(candidate_id)
        if not candidate.send_ready:
            raise QueueTransitionError("candidate is not approved/send-ready")
        # Generic payload only; callers choose a separately authorized
        # transport.  No transport is invoked by this method.
        return SendReady(candidate.candidate_id, candidate.source, candidate.recipient, candidate.proposed_reply, candidate.route)

    def send_intent_path(self, candidate_id: str) -> Path:
        """Return the deterministic local path for one candidate's intent."""

        candidate_id = str(candidate_id)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", candidate_id)
        if safe_name != candidate_id or not safe_name:
            import hashlib

            safe_name = "intent-" + hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()[:24]
        return self.send_intents_path / (safe_name + ".json")

    def mark_sent(self, candidate_id: str, *, ui_confirmed: bool = False, intent_path: Optional[Path] = None) -> ReplyCandidate:
        """Mark a candidate sent only after a human confirms a real UI send.

        This method never sends anything.  ``ui_confirmed`` is deliberately
        required so scheduled jobs cannot accidentally turn approval into a
        sent state.  A matching local send-intent is also required, allowing a
        reviewer to re-check recipient, route, summary, and body first.
        """

        if not ui_confirmed:
            raise QueueTransitionError("mark-sent requires explicit UI-success confirmation")
        candidate = self.get(candidate_id)
        if candidate.source not in ("line", "slack", "discord"):
            raise QueueTransitionError("source is not sendable: %s" % candidate.source)
        if candidate.status != "approved" or not candidate.send_ready:
            raise QueueTransitionError("only approved, non-blocked candidates can be marked sent")
        path = Path(intent_path) if intent_path else self.send_intent_path(candidate.candidate_id)
        if not path.exists():
            raise QueueTransitionError("matching send intent is required before mark-sent")
        try:
            intent = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise QueueTransitionError("cannot read send intent: %s" % type(exc).__name__)
        if not isinstance(intent, Mapping):
            raise QueueTransitionError("send intent has invalid shape")
        if str(intent.get("candidate_id", "")) != candidate.candidate_id:
            raise QueueTransitionError("send intent candidate mismatch")
        if str(intent.get("source", "")) != candidate.source:
            raise QueueTransitionError("send intent source mismatch")
        if str(intent.get("body", "")) != candidate.proposed_reply:
            raise QueueTransitionError("send intent body changed; re-review required")
        if str(intent.get("recipient", "")) != candidate.recipient:
            raise QueueTransitionError("send intent recipient changed; re-review required")
        if not isinstance(intent.get("route"), Mapping) or dict(intent.get("route") or {}) != dict(candidate.route):
            raise QueueTransitionError("send intent route changed; re-review required")
        if str(intent.get("summary", intent.get("original_summary", ""))) != candidate.original_summary:
            raise QueueTransitionError("send intent summary changed; re-review required")
        if str(intent.get("status", "")) not in ("send-ready", "awaiting_user_confirmation"):
            raise QueueTransitionError("send intent is not awaiting a UI send")
        if intent.get("external_send_enabled") is not False or intent.get("ui_confirmation_required") is not True:
            raise QueueTransitionError("send intent does not require explicit human confirmation")

        candidate.status = "sent"
        candidate.draft_only = False
        self._data["candidates"][candidate.candidate_id] = candidate.to_dict()
        self._save()
        intent = dict(intent)
        intent["status"] = "sent"
        intent["sent_at"] = datetime.now(timezone.utc).isoformat()
        intent["send_executed_by_life_iq"] = False
        _atomic_json_write(path, intent)
        return candidate
