# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Compatibility import for the X browser-capture adapter."""

from .x import XAdapter, PROMPT_INJECTION_NOTICE

__all__ = ["XAdapter", "PROMPT_INJECTION_NOTICE"]
