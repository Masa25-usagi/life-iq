# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""LINE adapter for already-captured Mac app/browser text.

No UI automation is performed here.  The bounded acquisition layer may open
ordinary 1:1 chats or group chats with a visible direct mention under the
runbook (and they may become read), but this parser/adapter itself never opens
conversations, clicks a chat, marks a message read, sends, replies, deletes,
or changes LINE settings.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional, Tuple
from pathlib import Path

from .base import AdapterResult, SourceStatus, SourceWindow, any_capture_flag, capture_receipt_status, explicit_capture_flag, in_window, make_event, read_json_records_with_fingerprint, stable_ref
from ..privacy import redact_text


_OPEN_CHAT_MARKERS = ("openchat", "open chat", "オープンチャット", "オープン チャット")
_OFFICIAL_MARKERS = ("official account", "official", "公式アカウント", "公式 アカウント")
_BUSINESS_STORE_MARKERS = (
    "business account",
    "business-account",
    "company account",
    "company-account",
    "store account",
    "store-account",
    "merchant account",
    "enterprise account",
    "企業アカウント",
    "企業公式",
    "店舗アカウント",
    "店舗公式",
    "ショップ公式",
    "法人アカウント",
    "法人公式",
)
_EXCLUDED_CONVERSATION_TYPES = frozenset(
    {
        "openchat",
        "open_chat",
        "official",
        "official_account",
        "business",
        "business_account",
        "company",
        "company_account",
        "store",
        "store_account",
        "merchant",
        "merchant_account",
        "enterprise",
        "enterprise_account",
        "corporate",
        "corporate_account",
    }
)
_EXCLUDED_ACCOUNT_FLAGS = (
    "is_openchat",
    "is_open_chat",
    "is_official",
    "is_official_account",
    "official_account",
    "is_business",
    "is_business_account",
    "business_account",
    "is_company",
    "is_company_account",
    "company_account",
    "is_store",
    "is_store_account",
    "store_account",
    "is_merchant",
    "is_merchant_account",
    "merchant_account",
    "is_enterprise",
    "is_enterprise_account",
    "enterprise_account",
    "is_corporate",
    "is_corporate_account",
    "corporate_account",
    "is_shop",
    "is_shop_account",
)


def _explicit_flag(value: Any) -> bool:
    """Interpret capture boolean flags without treating ``"false"`` as true."""
    return explicit_capture_flag(value)


def _normalized_type(value: Any) -> str:
    return str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")


def is_excluded_line_conversation(record: Mapping[str, Any]) -> bool:
    """Return true for LINE conversations outside the personal-account scope.

    OpenChat, official, business, company, store, merchant, and enterprise
    accounts are excluded before message extraction.  Metadata is checked
    before body text so excluded conversations do not pass through normal
    message extraction.  The body fallback handles captures where OCR exposed
    only a conversation heading.
    """

    metadata_record = record.get("metadata")
    flag_records = [record]
    if isinstance(metadata_record, Mapping):
        flag_records.append(metadata_record)
    if any(_explicit_flag(item.get(key)) for item in flag_records for key in _EXCLUDED_ACCOUNT_FLAGS):
        return True

    type_values = [
        record.get("conversation_type"),
        record.get("chat_type"),
        record.get("kind"),
        record.get("account_type"),
        record.get("category"),
        record.get("sender_type"),
    ]
    if isinstance(metadata_record, Mapping):
        type_values.extend(
            metadata_record.get(key) for key in ("conversation_type", "chat_type", "kind", "account_type", "category", "sender_type")
        )
    normalized_types = {_normalized_type(value) for value in type_values if value not in (None, "")}
    if normalized_types.intersection(_EXCLUDED_CONVERSATION_TYPES):
        return True
    metadata_fields = [
        record.get("conversation_name"),
        record.get("chat_name"),
        record.get("title"),
        record.get("account_name"),
        record.get("display_name"),
        record.get("profile_name"),
        record.get("business_category"),
        record.get("organization"),
        record.get("sender_type"),
        record.get("account_type"),
        record.get("category"),
    ]
    if isinstance(metadata_record, Mapping):
        metadata_fields.extend(metadata_record.values())
    metadata = " ".join(str(value) for value in metadata_fields if value is not None).lower()
    if any(marker in metadata for marker in _OPEN_CHAT_MARKERS + _OFFICIAL_MARKERS + _BUSINESS_STORE_MARKERS):
        return True
    # A body may contain a visible heading in OCR.  It is used only to decide
    # exclusion and is never emitted when a marker is found.
    body_values = [
        record.get("text"),
        record.get("ocr_text"),
        record.get("message"),
        record.get("transcript"),
    ]
    for key in ("observations", "elements", "nodes"):
        nested = record.get(key)
        if isinstance(nested, (list, tuple)):
            for item in nested:
                if isinstance(item, Mapping):
                    body_values.extend(item.get(field) for field in ("text", "value", "label", "content"))
                else:
                    body_values.append(item)
    body = " ".join(str(value) for value in body_values if value not in (None, "")).lower()
    return any(marker in body for marker in _OPEN_CHAT_MARKERS + _OFFICIAL_MARKERS + _BUSINESS_STORE_MARKERS)


def _timestamp(record: Mapping[str, Any]) -> Any:
    for key in ("occurred_at", "timestamp", "created_at", "time"):
        if record.get(key) not in (None, ""):
            return record[key]
    return None


def _is_line_capture(record: Mapping[str, Any]) -> bool:
    app = str(record.get("app") or record.get("application") or "").lower()
    if not app:
        return True  # injected records may already be LINE-scoped
    return bool(re.search(r"(?<![a-z0-9])line(?![a-z0-9.-])", app) or "ライン" in app)


class LineAdapter:
    source = "line"

    def __init__(self, path: Optional[Path] = None, records: Optional[Iterable[Mapping[str, Any]]] = None, *, logged_in: Optional[bool] = None) -> None:
        self.path = Path(path) if path else None
        self.records = list(records) if records is not None else None
        self.logged_in = logged_in

    def collect(self, window: SourceWindow, cursor: Optional[str] = None) -> AdapterResult:
        if self.logged_in is False:
            return AdapterResult(status=SourceStatus(self.source, "skipped", "LINE is logged out; no UI action was attempted"))
        if self.records is None:
            if self.path is None:
                return AdapterResult(status=SourceStatus(self.source, "skipped", "LINE app/browser capture is unavailable"))
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
        excluded = 0
        ignored = 0
        latest = cursor
        for record in records:
            if not _is_line_capture(record):
                continue
            # This flag is defensive: a self-identified traversal is never
            # accepted, even if a caller accidentally supplies such a record.
            if any_capture_flag(record, ("auto_traversed", "opened_unread", "adapter_action")):
                ignored += 1
                continue
            if is_excluded_line_conversation(record):
                excluded += 1
                continue
            timestamp = _timestamp(record)
            if timestamp is None or not in_window(timestamp, window):
                continue
            text = redact_text(record.get("text") or record.get("ocr_text") or record.get("message") or record.get("transcript") or "", max_chars=360)
            if not text:
                continue
            conversation = record.get("conversation_name") or record.get("chat_name") or record.get("title") or "LINE conversation"
            ref = record.get("message_id") or record.get("id") or stable_ref("line", timestamp, conversation, text)
            metadata = {
                "conversation_type": str(record.get("conversation_type") or "regular")[:40],
                "app_mode": str(record.get("app_mode") or "app/browser")[:40],
                "conversation_id": str(record.get("conversation_id") or record.get("chat_id") or "")[:120] or None,
                "conversation_name": str(conversation)[:140],
                "recipient": str(record.get("recipient") or record.get("participant") or "")[:140] or None,
                "is_self": any(explicit_capture_flag(record.get(key)) for key in ("is_self", "author_is_self", "self_authored")),
                "direction": str(record.get("direction") or "")[:30] or None,
                "is_direct_mention": any(
                    explicit_capture_flag(record.get(key))
                    for key in ("is_direct_mention", "mentions_self", "mentioned_user_is_self")
                ) or str(record.get("mentioned_user") or "").casefold() in ("self", "me", "本人"),
                "account_type": str(record.get("account_type") or "")[:50] or None,
            }
            events.append(
                make_event(
                    source=self.source,
                    source_ref=str(ref),
                    timestamp=timestamp,
                    event_type="conversation",
                    summary_parts=("LINE", conversation, text),
                    entities=record.get("entities") or record.get("participants") or [],
                    confidence=0.68,
                    metadata=metadata,
                )
            )
            latest = str(timestamp)
        status_message = "read-only captured LINE text; excluded=%d ignored=%d" % (excluded, ignored)
        if diagnostic:
            status_message += "; " + diagnostic
        return AdapterResult(events=events, status=SourceStatus(self.source, "success", status_message, latest, len(events)))
