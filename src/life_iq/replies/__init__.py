# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Reply candidate generation and local approval queue.

This package deliberately stops at a human-approved ``send-ready`` payload;
it has no network/UI sender.
"""

from .candidates import (
    BLOCKING_RISK_FLAGS,
    Candidate,
    ReplyCandidate,
    ReplyCandidateBuilder,
    build_reply_candidates,
    detect_risk_flags,
    detect_risks,
    risk_flags_for_event,
)
from .queue import (
    ExternalActionDisabled,
    QueueTransitionError,
    ReplyQueue,
    ReadOnlySendAdapter,
    SendAdapter,
    SendReady,
)

__all__ = [
    "BLOCKING_RISK_FLAGS",
    "Candidate",
    "ReplyCandidate",
    "ReplyCandidateBuilder",
    "build_reply_candidates",
    "detect_risk_flags",
    "detect_risks",
    "risk_flags_for_event",
    "ExternalActionDisabled",
    "QueueTransitionError",
    "ReplyQueue",
    "ReadOnlySendAdapter",
    "SendAdapter",
    "SendReady",
]
