# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Life IQ: a read-only local life-context ingestion pipeline.

The package intentionally uses only the Python standard library.  Source
adapters accept local exports/captures or injected records, which keeps the
default installation safe when an app is logged out or credentials are not
configured.
"""

from .config import Config, ConfigError, load_config
from .capture import CaptureBridge, CaptureImportError, CaptureImportResult, CaptureStatus
from .schema import NormalizedEvent
from .replies import ReplyCandidate, ReplyCandidateBuilder, ReplyQueue
from .send_intents import SendIntent, SendIntentError, materialize_send_intent

__all__ = [
    "Config",
    "ConfigError",
    "CaptureBridge",
    "CaptureImportError",
    "CaptureImportResult",
    "CaptureStatus",
    "NormalizedEvent",
    "ReplyCandidate",
    "ReplyCandidateBuilder",
    "ReplyQueue",
    "SendIntent",
    "SendIntentError",
    "materialize_send_intent",
    "load_config",
]
__version__ = "0.1.0"
