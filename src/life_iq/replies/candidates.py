# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Reply candidate model and source-specific eligibility rules.

All capture text is untrusted data.  It is summarized/redacted and never
interpreted as an instruction, evaluated, or passed to a UI automation path.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

from ..privacy import contains_sensitive, redact_mapping, redact_text, sensitivity_for
from ..schema import NormalizedEvent, canonical_json, parse_datetime


VALID_STATUSES = {"pending", "blocked", "approved", "rejected", "sent"}

# These flags are intentionally conservative.  A candidate with any of them
# remains a draft and can never transition to approved/send-ready.
BLOCKING_RISK_FLAGS = frozenset(
    {
        "financial",
        "purchase",
        "contract",
        "school",
        "medical",
        "legal",
        "safety",
        "romance",
        "sexual",
        "conflict",
        "apology",
        "personal_info",
        "auth_info",
        "attachment",
        "suspicious_link",
    }
)

_EXCLUDED_LINE = (
    "openchat",
    "open chat",
    "オープンチャット",
    "オープン チャット",
    "official account",
    "公式アカウント",
    "公式 アカウント",
    "企業アカウント",
    "店舗アカウント",
    "business account",
    "store account",
)
_BROAD_MENTIONS = ("@channel", "@here", "@everyone", "<!channel>", "<!here>", "<!everyone>", "全体通知", "全員通知")


def _metadata(event: NormalizedEvent) -> Mapping[str, Any]:
    return event.metadata if isinstance(event.metadata, Mapping) else {}


def _text(event: NormalizedEvent) -> str:
    # Only classification metadata is included.  Route IDs and display names
    # are intentionally omitted so a numeric conversation ID cannot look like
    # a phone/card number to the risk detector.  None of this is copied into a
    # proposed reply.
    metadata = _metadata(event)
    keys = (
        "risk_flags", "risk", "safety_flags", "has_attachment", "attachment",
        "attachments", "file_attached", "contains_attachment", "suspicious_link",
        "unsafe_link", "is_school_workspace", "conversation_type", "chat_type",
        "account_type", "category", "mention_type",
    )
    selected = {key: metadata.get(key) for key in keys if key in metadata}
    return event.summary + " " + json.dumps(selected, ensure_ascii=False, default=str)


def _norm(value: Any) -> str:
    return str(value or "").strip().casefold()


def _truthy(metadata: Mapping[str, Any], *keys: str) -> bool:
    return any(bool(metadata.get(key)) for key in keys)


def _direction(event: NormalizedEvent) -> str:
    metadata = _metadata(event)
    direction = _norm(metadata.get("direction"))
    if direction in ("outbound", "outgoing", "sent", "self", "from_me", "me"):
        return "outbound"
    if direction in ("inbound", "incoming", "received", "from_other", "other"):
        return "inbound"
    self_keys = ("is_self", "author_is_self", "self_authored", "sender_is_self", "from_self", "own_post")
    if any(key in metadata for key in self_keys):
        return "outbound" if _truthy(metadata, *self_keys) else "inbound"
    return "inbound"


def _conversation_key(event: NormalizedEvent) -> str:
    metadata = _metadata(event)
    if event.source == "slack" and metadata.get("thread_id") not in (None, ""):
        channel = metadata.get("conversation_id") or metadata.get("channel_id") or metadata.get("channel_name") or "channel"
        return "%s:%s:%s" % (event.source, _norm(channel), _norm(metadata.get("thread_id")))
    for key in ("conversation_id", "chat_id", "channel_id", "dm_id", "recipient", "conversation_name", "channel_name", "server_id"):
        value = metadata.get(key)
        if value not in (None, ""):
            return "%s:%s" % (event.source, _norm(value))
    return "%s:%s" % (event.source, event.source_ref)


def _safe_url(value: Any) -> str:
    value = redact_text(value, max_chars=240)
    try:
        parsed = urlsplit(value)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    except ValueError:
        return value


def _safe_route(event: NormalizedEvent) -> Dict[str, Any]:
    metadata = _metadata(event)
    route: Dict[str, Any] = {"reply_to_id": event.source_ref, "conversation_id": metadata.get("conversation_id") or metadata.get("chat_id") or metadata.get("channel_id")}
    source = event.source
    if source == "slack":
        route.update(
            {
                "workspace_name": redact_text(metadata.get("workspace_name"), max_chars=120),
                "workspace_url": _safe_url(metadata.get("workspace_url")),
                "workspace_id": redact_text(metadata.get("workspace_id"), max_chars=120),
                "channel_id": redact_text(metadata.get("channel_id"), max_chars=120),
                "channel_name": redact_text(metadata.get("channel_name"), max_chars=140),
                "thread_id": redact_text(metadata.get("thread_id") or metadata.get("thread_ts"), max_chars=140),
            }
        )
    elif source == "line":
        route.update(
            {
                "conversation_name": redact_text(metadata.get("conversation_name"), max_chars=140),
                "recipient": redact_text(metadata.get("recipient"), max_chars=140),
            }
        )
    elif source == "discord":
        route.update(
            {
                "server_id": redact_text(metadata.get("server_id"), max_chars=120),
                "server_name": redact_text(metadata.get("server_name"), max_chars=140),
                "recipient": redact_text(metadata.get("recipient"), max_chars=140),
            }
        )
    # Remove empty values while retaining route keys meaningful to callers.
    return {key: value for key, value in redact_mapping(route).items() if value not in (None, "")}


def _recipient(event: NormalizedEvent, route: Mapping[str, Any]) -> str:
    metadata = _metadata(event)
    source = event.source
    if source == "slack":
        if metadata.get("is_dm") or metadata.get("scope") == "dm":
            return redact_text(metadata.get("recipient") or metadata.get("conversation_name") or "Slack DM", max_chars=180)
        workspace = metadata.get("workspace_name") or metadata.get("workspace_url") or "Slack workspace"
        channel = metadata.get("channel_name") or metadata.get("conversation_name") or "Slack channel"
        return redact_text("%s / %s" % (workspace, channel), max_chars=220)
    if source == "line":
        return redact_text(metadata.get("recipient") or metadata.get("conversation_name") or "LINE conversation", max_chars=180)
    if source == "discord":
        return redact_text(metadata.get("recipient") or metadata.get("conversation_name") or "Discord DM", max_chars=180)
    return redact_text(metadata.get("recipient") or source, max_chars=180)


def _conversation(event: NormalizedEvent, route: Mapping[str, Any]) -> str:
    metadata = _metadata(event)
    if event.source == "slack":
        return redact_text("%s / %s" % (metadata.get("workspace_name") or "Slack workspace", metadata.get("channel_name") or metadata.get("conversation_name") or "conversation"), max_chars=220)
    return redact_text(metadata.get("conversation_name") or metadata.get("channel_name") or metadata.get("conversation_id") or _recipient(event, route), max_chars=220)


def _candidate_id(source: str, inbound_id: str) -> str:
    digest = hashlib.sha256((source + "\0" + inbound_id).encode("utf-8")).hexdigest()[:24]
    return "reply-%s" % digest


def _asked_schedule(text: str) -> bool:
    return bool(re.search(r"(?:いつ|何時|予定|日程|空いて|都合|when|schedule|available|availability|free\s+on)", text, re.I))


def _asked_opinion(text: str) -> bool:
    return bool(re.search(r"(?:どう思|意見|考え|感想|賛成|反対|what\s+do\s+you\s+think|opinion|thoughts?|agree)", text, re.I))


def detect_risk_flags(event: NormalizedEvent) -> Tuple[str, ...]:
    """Return stable, conservative risk labels for one inbound event."""

    metadata = _metadata(event)
    text = _text(event)
    lowered = text.casefold()
    flags: Set[str] = set()
    if re.search(r"(?:金銭|お金|代金|支払|振込|振り込|請求|返金|money|payment|invoice|\$|¥|€)", text, re.I):
        flags.add("financial")
    if re.search(r"(?:購入|注文|買う|買って|purchase|order|buy|shopping)", text, re.I):
        flags.add("purchase")
    if re.search(r"(?:契約|contract|agreement|terms\s+and\s+conditions)", text, re.I):
        flags.add("contract")
    if re.search(r"(?:学校|授業|school|class|teacher|先生).*(?:期限|締切|欠席|休む|成績|評価|処分|停学|退学|deadline|absence|grade|discipline)", text, re.I) or re.search(r"(?:欠席|成績|停学|退学|school\s+deadline|school\s+absence|school\s+grade)", text, re.I):
        flags.add("school")
    if re.search(r"(?:医療|病院|診断|薬|症状|medical|doctor|diagnosis|medicine|symptom)", text, re.I):
        flags.add("medical")
    if re.search(r"(?:法律|法務|弁護士|裁判|legal|lawyer|court)", text, re.I):
        flags.add("legal")
    if re.search(r"(?:安全|危険|警察|事故|脅迫|safety|danger|police|accident|threat)", text, re.I):
        flags.add("safety")
    if re.search(r"(?:恋愛|交際|彼氏|彼女|好き|恋人|romance|dating|boyfriend|girlfriend|love)", text, re.I):
        flags.add("romance")
    if re.search(r"(?:性的|性行為|アダルト|sexual|sex|nsfw)", text, re.I):
        flags.add("sexual")
    if re.search(r"(?:対立|喧嘩|口論|揉め|争い|conflict|fight|argument|dispute)", text, re.I):
        flags.add("conflict")
    if re.search(r"(?:謝罪|謝る|ごめん|すみません|apolog(?:y|ize|etic)|sorry)", text, re.I):
        flags.add("apology")
    if re.search(r"(?:個人情報|住所|電話番号|メールアドレス|phone\s*(?:number)?|email\s*address|personal\s+information)", text, re.I) or re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, re.I) or re.search(r"(?<![A-Za-z])\+?\d[\d -]{7,}\d", text):
        flags.add("personal_info")
    if contains_sensitive(text) or sensitivity_for(text) == "restricted":
        flags.add("auth_info")
    if any(bool(metadata.get(key)) for key in ("has_attachment", "attachment", "attachments", "file_attached", "contains_attachment")) or re.search(r"(?:添付|attachment|attached\s+file|ファイルを送)", text, re.I):
        flags.add("attachment")
    if bool(metadata.get("is_school_workspace")) and re.search(r"(?:期限|締切|欠席|成績|評価|処分|absence|grade|deadline|discipline)", text, re.I):
        flags.add("school")
    suspicious = bool(metadata.get("suspicious_link") or metadata.get("unsafe_link"))
    for url in re.findall(r"https?://[^\s<>]+", text, flags=re.I):
        host = _norm(urlsplit(url).netloc)
        if any(shortener in host for shortener in ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly")) or re.search(r"(?:token|auth|code|redirect|login)=", url, re.I):
            suspicious = True
    if suspicious:
        flags.add("suspicious_link")
    if _asked_schedule(event.summary):
        flags.add("schedule_requires_confirmation")
    if _asked_opinion(event.summary):
        flags.add("opinion_requires_confirmation")
    return tuple(sorted(flags))


def _direct_mention(event: NormalizedEvent) -> bool:
    metadata = _metadata(event)
    if _truthy(metadata, "is_direct_mention", "direct_mention", "mentions_self", "mentioned_user_is_self", "notification_for_self"):
        return True
    mention_type = _norm(metadata.get("mention_type"))
    if mention_type in ("direct", "user", "self"):
        return True
    mentions = metadata.get("mentions")
    if isinstance(mentions, (list, tuple)):
        return any(_norm(item) in ("self", "me", "本人", "user") or (isinstance(item, Mapping) and _truthy(item, "is_self", "is_current_user")) for item in mentions)
    return False


def _has_broadcast(text: str) -> bool:
    return any(marker.casefold() in text.casefold() for marker in _BROAD_MENTIONS)


def _line_allowed(event: NormalizedEvent) -> bool:
    metadata = _metadata(event)
    combined = " ".join(str(metadata.get(key, "")) for key in ("conversation_type", "chat_type", "account_type", "category", "conversation_name", "recipient")) + " " + event.summary
    lowered = combined.casefold()
    if any(marker.casefold() in lowered for marker in _EXCLUDED_LINE) or _truthy(metadata, "is_official", "is_openchat", "is_business", "is_store", "is_company"):
        return False
    kind = _norm(metadata.get("conversation_type") or metadata.get("chat_type") or metadata.get("kind"))
    if kind in ("group", "group_chat", "groupchat") or _truthy(metadata, "is_group"):
        return _direct_mention(event)
    return kind not in ("official", "official_account", "openchat", "open_chat", "business", "store")


def _slack_allowed(event: NormalizedEvent) -> bool:
    metadata = _metadata(event)
    text = _text(event)
    if _has_broadcast(text) or _norm(metadata.get("mention_type")) in ("channel", "here", "everyone", "broadcast"):
        return False
    if bool(metadata.get("is_dm") or metadata.get("scope") == "dm"):
        return True
    return _direct_mention(event)


def _allowlisted_server(event: NormalizedEvent, allowlist: Sequence[str]) -> bool:
    if not allowlist:
        return False
    metadata = _metadata(event)
    values = {
        _norm(metadata.get("server_id")),
        _norm(metadata.get("server_name")),
        _norm(metadata.get("guild_id")),
        _norm(metadata.get("guild_name")),
    }
    values.discard("")
    return any(_norm(item) in values for item in allowlist)


def _mutual_days(event: NormalizedEvent, events: Sequence[NormalizedEvent]) -> int:
    metadata = _metadata(event)
    explicit = metadata.get("mutual_days")
    try:
        if explicit is not None:
            return int(explicit)
    except (TypeError, ValueError):
        pass
    key = _conversation_key(event)
    cutoff = event.occurred_at - timedelta(days=90)
    inbound_days: Set[Any] = set()
    outbound_days: Set[Any] = set()
    for item in events:
        if item.source != "discord" or _conversation_key(item) != key:
            continue
        if not (cutoff <= item.occurred_at <= event.occurred_at):
            continue
        if _direction(item) == "outbound":
            outbound_days.add(item.occurred_at.date())
        else:
            inbound_days.add(item.occurred_at.date())
    return len(inbound_days.intersection(outbound_days))


def _discord_allowed(event: NormalizedEvent, events: Sequence[NormalizedEvent], server_allowlist: Sequence[str]) -> bool:
    metadata = _metadata(event)
    is_dm = bool(metadata.get("is_dm") or metadata.get("scope") == "dm")
    if is_dm:
        return _mutual_days(event, events) >= 3
    return _allowlisted_server(event, server_allowlist)


def _is_inbound(event: NormalizedEvent) -> bool:
    return _direction(event) == "inbound"


def _has_followup(event: NormalizedEvent, events: Sequence[NormalizedEvent]) -> bool:
    key = _conversation_key(event)
    return any(
        item.source == event.source
        and _conversation_key(item) == key
        and item.occurred_at > event.occurred_at
        and _direction(item) == "outbound"
        for item in events
    )


def _proposed_reply(event: NormalizedEvent) -> str:
    metadata = _metadata(event)
    if event.source == "discord":
        reply = "AI代理の暫定返信案です。受け取りました。本人があとで確認して、必要なら返信します。"
    elif event.source == "line":
        reply = "AI代理による暫定返信案です。受け取りました。本人が後で確認し、必要に応じて返信します。"
    else:
        reply = "AI代理による暫定返信案です。受け取りました。本人が後で確認し、必要に応じて返信します。"
    text = event.summary
    additions = []
    if _asked_schedule(text):
        additions.append("日程については未確定で、本人確認が必要です。確定した予定は表明しません。")
    if _asked_opinion(text):
        additions.append("意見については未確定で、本人確認が必要です。本人の意見を推測して表明しません。")
    if additions:
        reply += " " + " ".join(additions)
    return redact_text(reply, max_chars=800)


@dataclass
class ReplyCandidate:
    """A human-reviewable, source-routed reply draft."""

    candidate_id: str
    source: str
    recipient: str
    conversation: str
    inbound_id: str
    inbound_timestamp: datetime
    original_summary: str
    proposed_reply: str
    risk_flags: Tuple[str, ...] = field(default_factory=tuple)
    status: str = "pending"
    route: Mapping[str, Any] = field(default_factory=dict)
    thread_info: Mapping[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    draft_only: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        self.source = str(self.source).strip().lower()
        self.inbound_timestamp = parse_datetime(self.inbound_timestamp)
        self.created_at = parse_datetime(self.created_at)
        self.recipient = redact_text(self.recipient, max_chars=220)
        self.conversation = redact_text(self.conversation, max_chars=240)
        self.inbound_id = redact_text(self.inbound_id, max_chars=180)
        self.original_summary = redact_text(self.original_summary, max_chars=600)
        self.proposed_reply = redact_text(self.proposed_reply, max_chars=900)
        self.risk_flags = tuple(sorted(set(str(flag).strip() for flag in self.risk_flags if str(flag).strip())))
        self.status = str(self.status).strip().lower()
        if self.status not in VALID_STATUSES:
            raise ValueError("invalid reply candidate status: %s" % self.status)
        self.route = redact_mapping(dict(self.route or {}))
        self.thread_info = redact_mapping(dict(self.thread_info or {}))
        self.note = redact_text(self.note, max_chars=400)
        if not self.candidate_id:
            self.candidate_id = _candidate_id(self.source, self.inbound_id)
        if set(self.risk_flags).intersection(BLOCKING_RISK_FLAGS):
            self.draft_only = True

    @property
    def is_blocked(self) -> bool:
        return self.status == "blocked" or bool(set(self.risk_flags).intersection(BLOCKING_RISK_FLAGS))

    @property
    def send_ready(self) -> bool:
        return self.status == "approved" and not self.is_blocked and not self.draft_only

    @property
    def inbound_at(self) -> datetime:
        return self.inbound_timestamp

    @property
    def route_info(self) -> Mapping[str, Any]:
        """Alias used by integrations that call routing metadata route_info."""
        return self.route

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source": self.source,
            "recipient": self.recipient,
            "conversation": self.conversation,
            "inbound_id": self.inbound_id,
            "inbound_timestamp": self.inbound_timestamp.isoformat(),
            "original_summary": self.original_summary,
            "proposed_reply": self.proposed_reply,
            "risk_flags": list(self.risk_flags),
            "status": self.status,
            "route": dict(self.route),
            "thread_info": dict(self.thread_info),
            "created_at": self.created_at.isoformat(),
            "draft_only": self.draft_only,
            "send_ready": self.send_ready,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReplyCandidate":
        return cls(
            candidate_id=str(value.get("candidate_id", "")),
            source=str(value.get("source", "")),
            recipient=str(value.get("recipient", "")),
            conversation=str(value.get("conversation", "")),
            inbound_id=str(value.get("inbound_id", "")),
            inbound_timestamp=parse_datetime(value.get("inbound_timestamp") or value.get("inbound_at")),
            original_summary=str(value.get("original_summary", "")),
            proposed_reply=str(value.get("proposed_reply", "")),
            risk_flags=tuple(value.get("risk_flags") or ()),
            status=str(value.get("status", "pending")),
            route=dict(value.get("route") or {}),
            thread_info=dict(value.get("thread_info") or {}),
            created_at=parse_datetime(value.get("created_at"), default=datetime.now(timezone.utc)),
            draft_only=bool(value.get("draft_only", False)),
            note=str(value.get("note", "")),
        )


Candidate = ReplyCandidate


class ReplyCandidateBuilder:
    def __init__(self, *, discord_server_allowlist: Optional[Iterable[str]] = None, context_text: str = "", now: Optional[datetime] = None) -> None:
        self.discord_server_allowlist = tuple(str(item) for item in (discord_server_allowlist or ()) if str(item).strip())
        # Context is intentionally not used to infer dates/opinions or facts.
        # Keeping the argument allows a later reviewer to display context
        # provenance without letting captured text become executable prompts.
        self.context_text = ""
        self.now = parse_datetime(now or datetime.now(timezone.utc))

    def build(
        self,
        events: Iterable[NormalizedEvent],
        *,
        discovery_start: Optional[datetime] = None,
        discovery_end: Optional[datetime] = None,
        discovered_at: Optional[datetime] = None,
    ) -> List[ReplyCandidate]:
        all_events = sorted(list(events), key=lambda item: (item.occurred_at, item.event_id))
        start = parse_datetime(discovery_start) if discovery_start is not None else None
        end = parse_datetime(discovery_end) if discovery_end is not None else None
        result: Dict[str, ReplyCandidate] = {}
        created = parse_datetime(discovered_at or self.now)
        for event in all_events:
            if event.source not in ("line", "slack", "discord") or event.source == "x":
                continue
            if not _is_inbound(event) or _has_followup(event, all_events):
                continue
            if start is not None and event.occurred_at < start:
                continue
            if end is not None and event.occurred_at >= end:
                continue
            if event.source == "line" and not _line_allowed(event):
                continue
            if event.source == "slack" and not _slack_allowed(event):
                continue
            if event.source == "discord" and not _discord_allowed(event, all_events, self.discord_server_allowlist):
                continue
            flags = detect_risk_flags(event)
            route = _safe_route(event)
            candidate = ReplyCandidate(
                candidate_id=_candidate_id(event.source, event.source_ref),
                source=event.source,
                recipient=_recipient(event, route),
                conversation=_conversation(event, route),
                inbound_id=event.source_ref,
                inbound_timestamp=event.occurred_at,
                original_summary=event.summary,
                proposed_reply=_proposed_reply(event),
                risk_flags=flags,
                status="blocked" if set(flags).intersection(BLOCKING_RISK_FLAGS) else "pending",
                route=route,
                thread_info={"thread_id": route.get("thread_id"), "reply_to_id": route.get("reply_to_id")} if event.source == "slack" else {"conversation_id": route.get("conversation_id"), "reply_to_id": route.get("reply_to_id")},
                created_at=created,
                draft_only=bool(set(flags).intersection(BLOCKING_RISK_FLAGS)),
                note="送信前に本人の確認が必要です。" if flags else "AI代理の暫定返信案です。本人が後で確認してください。",
            )
            result[candidate.candidate_id] = candidate
        return sorted(result.values(), key=lambda item: (item.inbound_timestamp, item.candidate_id))

    def build_candidates(self, events: Iterable[NormalizedEvent], **kwargs: Any) -> List[ReplyCandidate]:
        return self.build(events, **kwargs)


def build_reply_candidates(events: Iterable[NormalizedEvent], **kwargs: Any) -> List[ReplyCandidate]:
    return ReplyCandidateBuilder(**{key: value for key, value in kwargs.items() if key in ("discord_server_allowlist", "context_text", "now")}).build(
        events,
        discovery_start=kwargs.get("discovery_start"),
        discovery_end=kwargs.get("discovery_end"),
        discovered_at=kwargs.get("discovered_at"),
    )


detect_risks = detect_risk_flags
risk_flags_for_event = detect_risk_flags
