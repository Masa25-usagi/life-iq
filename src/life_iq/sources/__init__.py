# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Read-only source adapters."""

from .base import AdapterResult, SourceAdapter, SourceStatus, SourceWindow
from .gmail import GmailAdapter
from .drive import DriveAdapter
from .screenpipe import ScreenpipeAdapter
from .line import LineAdapter, is_excluded_line_conversation
from .discord import DiscordAdapter
from .x import XAdapter
from .slack import SlackAdapter

__all__ = [
    "AdapterResult",
    "SourceAdapter",
    "SourceStatus",
    "SourceWindow",
    "GmailAdapter",
    "DriveAdapter",
    "ScreenpipeAdapter",
    "LineAdapter",
    "DiscordAdapter",
    "XAdapter",
    "SlackAdapter",
    "is_excluded_line_conversation",
]
