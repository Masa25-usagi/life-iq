# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Discord adapter for already-captured app/browser text.

Only DMs and servers for which the user's own message history is visible in
the supplied capture are accepted.  This module never searches servers or
channels and performs no Discord write/read-state operation.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional, Set
from pathlib import Path
from urllib.parse import urlsplit

from .base import AdapterResult, SourceStatus, SourceWindow, any_capture_flag, capture_receipt_status, in_window, make_event, read_json_records_with_fingerprint, stable_ref
from ..privacy import redact_text


def _timestamp(record: Mapping[str, Any]) -> Any:
    for key in ("occurred_at", "timestamp", "created_at", "time"):
        if record.get(key) not in (None, ""):
            return record[key]
    return None


def _is_discord_capture(record: Mapping[str, Any]) -> bool:
    app = str(record.get("app") or record.get("application") or "").lower()
    return not app or bool(re.search(r"(?<![a-z0-9])discord(?![a-z0-9.-])", app))


def _has_discord_service_evidence(record: Mapping[str, Any]) -> bool:
    source = str(record.get("source") or record.get("source_name") or record.get("capture_source") or "").strip().casefold()
    if source in ("discord", "discord_app", "discord_browser"):
        return True
    app = str(record.get("app") or record.get("application") or "").casefold()
    if re.search(r"(?<![a-z0-9])discord(?![a-z0-9.-])", app):
        return True
    for key in ("url", "page_url", "browser_url"):
        try:
            hostname = (urlsplit(str(record.get(key) or "")).hostname or "").casefold()
        except ValueError:
            hostname = ""
        if hostname == "discord.com" or hostname.endswith(".discord.com") or hostname == "discordapp.com":
            return True
    return False


def _is_self(record: Mapping[str, Any], current_user_id: Optional[str]) -> bool:
    if any_capture_flag(record, ("is_self", "author_is_self", "self_authored")):
        return True
    if current_user_id and str(record.get("author_id") or "") == str(current_user_id):
        return True
    return False


def _is_dm(record: Mapping[str, Any]) -> bool:
    if any_capture_flag(record, ("is_dm", "dm")):
        return True
    kind = str(record.get("conversation_type") or record.get("channel_type") or record.get("kind") or "").lower()
    return kind in ("dm", "direct_message", "direct-message", "group_dm")


class DiscordAdapter:
    source = "discord"

    def __init__(self, path: Optional[Path] = None, records: Optional[Iterable[Mapping[str, Any]]] = None, *, current_user_id: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self.records = list(records) if records is not None else None
        self.current_user_id = current_user_id

    def collect(self, window: SourceWindow, cursor: Optional[str] = None) -> AdapterResult:
        if self.records is None:
            if self.path is None:
                return AdapterResult(status=SourceStatus(self.source, "skipped", "Discord app/browser capture is unavailable"))
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

        # Establish the allowlist only from explicit evidence of the user's
        # own post or a trusted capture field.  Merely seeing a server name is
        # not enough to make it eligible.
        eligible_servers: Set[str] = set()
        for record in records:
            server_id = record.get("server_id") or record.get("guild_id")
            if not _has_discord_service_evidence(record) or not server_id or _is_dm(record):
                continue
            if any_capture_flag(record, ("auto_traversed", "opened_unread", "adapter_action")):
                continue
            timestamp = _timestamp(record)
            if timestamp is None or not in_window(timestamp, window):
                continue
            if _is_self(record, self.current_user_id) or any_capture_flag(record, ("has_user_sent", "user_has_posted", "server_user_message_history")):
                eligible_servers.add(str(server_id))

        events = []
        excluded_servers = 0
        ignored = 0
        latest = cursor
        for record in records:
            if not _is_discord_capture(record):
                continue
            if any_capture_flag(record, ("auto_traversed", "opened_unread", "adapter_action")):
                ignored += 1
                continue
            is_dm = _is_dm(record)
            server_id = record.get("server_id") or record.get("guild_id")
            if not is_dm and (not server_id or str(server_id) not in eligible_servers):
                excluded_servers += 1
                continue
            timestamp = _timestamp(record)
            if timestamp is None or not in_window(timestamp, window):
                continue
            text = redact_text(record.get("text") or record.get("message") or record.get("content") or "", max_chars=360)
            if not text:
                continue
            location = record.get("server_name") or record.get("channel_name") or ("DM" if is_dm else "server")
            ref = record.get("message_id") or record.get("id") or stable_ref("discord", timestamp, server_id or "dm", location, text)
            events.append(
                make_event(
                    source=self.source,
                    source_ref=str(ref),
                    timestamp=timestamp,
                    event_type="conversation",
                    summary_parts=("Discord", location, text),
                    entities=record.get("entities") or record.get("participants") or [],
                    confidence=0.7,
                    metadata={
                        "scope": "dm" if is_dm else "eligible_server",
                        "server_id": str(server_id) if server_id else None,
                        "server_name": str(record.get("server_name") or "")[:140] or None,
                        "conversation_id": str(record.get("conversation_id") or record.get("channel_id") or record.get("dm_id") or "")[:140] or None,
                        "recipient": str(record.get("recipient") or record.get("dm_recipient") or record.get("participant") or "")[:140] or None,
                        "is_dm": is_dm,
                        "is_self": _is_self(record, self.current_user_id),
                        "direction": str(record.get("direction") or "")[:30] or None,
                        "is_direct_mention": any_capture_flag(record, ("is_direct_mention", "mentions_self", "mentioned_user")),
                    },
                )
            )
            latest = str(timestamp)
        status_message = "read-only captured Discord text; eligible_servers=%d excluded=%d ignored=%d" % (len(eligible_servers), excluded_servers, ignored)
        if diagnostic:
            status_message += "; " + diagnostic
        return AdapterResult(events=events, status=SourceStatus(self.source, "success", status_message, latest, len(events)))
