"""Privacy filtering for summaries and safe metadata.

The ingestion process is intentionally lossy.  It keeps enough text to
identify an event while removing credentials, one-time codes, payment data,
and high-risk health/sexual details before anything is written to disk.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping


_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:password|passwd|passphrase|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|secret|bearer)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\b(?:authorization\s+)?bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(?:otp|one[- ]?time\s+password|verification|auth(?:entication)?\s*code|認証コード|ワンタイム)\s*[:=]?\s*\d{4,10}\b"),
    re.compile(r"(?i)\b(?:カード番号|credit\s*card|card\s*number)\s*[:=]?\s*[0-9][0-9 -]{10,24}"),
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    re.compile(r"(?i)\b(?:bank\s*(?:account|balance)|routing\s*number|口座番号|銀行残高)\s*[:=]?\s*[^\s,;]+"),
    re.compile(r"(?i)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)

_HIGH_RISK_MARKERS = (
    "medical",
    "diagnosis",
    "病名",
    "診断",
    "カルテ",
    "sexual",
    "sex life",
    "性的",
    "性行為",
)

_SENSITIVE_MARKERS = (
    "phone",
    "tel",
    "電話",
    "address",
    "住所",
    "email",
    "メール",
)


def _replace(match: re.Match) -> str:
    return "[REDACTED]"


def redact_text(value: Any, max_chars: int = 600) -> str:
    """Redact high-risk tokens and bound text persisted to artifacts."""

    text = "" if value is None else str(value)
    if any(marker.lower() in text.lower() for marker in _HIGH_RISK_MARKERS):
        return "[REDACTED]"
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_replace, text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    return text


def contains_sensitive(value: Any) -> bool:
    text = "" if value is None else str(value)
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in _HIGH_RISK_MARKERS) or any(
        pattern.search(text) for pattern in _SECRET_PATTERNS
    )


def sensitivity_for(value: Any) -> str:
    text = "" if value is None else str(value)
    lowered = text.lower()
    if any(marker.lower() in lowered for marker in _HIGH_RISK_MARKERS) or any(
        pattern.search(text) for pattern in _SECRET_PATTERNS
    ):
        return "restricted"
    if any(marker.lower() in lowered for marker in _SENSITIVE_MARKERS):
        return "sensitive"
    return "normal"


def redact_mapping(value: Any, max_chars: int = 600) -> Any:
    """Recursively sanitize a JSON-like mapping without retaining raw text."""

    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if any(marker in key_text.lower() for marker in ("password", "token", "secret", "credential", "auth_code")):
                result[key_text] = "[REDACTED]"
            else:
                result[key_text] = redact_mapping(item, max_chars=max_chars)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_mapping(item, max_chars=max_chars) for item in value]
    if isinstance(value, str):
        return redact_text(value, max_chars=max_chars)
    return value


def safe_summary(*parts: Any, max_chars: int = 600) -> str:
    """Join source fragments, redact them, and remove empty fragments."""

    joined = " — ".join(str(part).strip() for part in parts if part is not None and str(part).strip())
    return redact_text(joined, max_chars=max_chars)
