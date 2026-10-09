# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Compatibility import for the Slack browser-capture adapter."""

from .slack import SlackAdapter, PROMPT_INJECTION_NOTICE

__all__ = ["SlackAdapter", "PROMPT_INJECTION_NOTICE"]
