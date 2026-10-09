# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Configuration loading and validation.

The parser accepts JSON and the small TOML subset used by the checked-in
example.  This avoids a network-installed dependency on machines that ship
only Python 3.9.
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple


class ConfigError(ValueError):
    """Raised when configuration is malformed or unsafe."""


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        try:
            return str(ast.literal_eval(value))
        except (ValueError, SyntaxError):
            return value[1:-1]
    return value


def _parse_toml_scalar(value: str) -> Any:
    value = value.strip()
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    if value.startswith("[") and value.endswith("]"):
        inside = value[1:-1].strip()
        if not inside:
            return []
        # The checked-in config only uses simple arrays.  Splitting while
        # respecting quoted commas makes it useful for small user configs too.
        items = []
        current = []
        quote = None
        for char in inside:
            if char in ('"', "'") and (not quote or quote == char):
                quote = None if quote else char
            if char == "," and not quote:
                items.append(_parse_toml_scalar("".join(current)))
                current = []
            else:
                current.append(char)
        if current:
            items.append(_parse_toml_scalar("".join(current)))
        return items
    unquoted = _unquote(value)
    if unquoted != value:
        return unquoted
    try:
        return float(value) if "." in value else int(value)
    except ValueError:
        return value


def _parse_simple_toml(text: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    section: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = [part.strip() for part in line[1:-1].split(".") if part.strip()]
            continue
        if "=" not in line:
            raise ConfigError("invalid config line: %s" % raw_line)
        key, raw_value = line.split("=", 1)
        key = key.strip()
        # Remove comments outside quotes.
        quote = None
        value_chars = []
        for char in raw_value:
            if char in ('"', "'") and (not quote or quote == char):
                quote = None if quote else char
            if char == "#" and not quote:
                break
            value_chars.append(char)
        value = _parse_toml_scalar("".join(value_chars))
        target = result
        for part in section:
            target = target.setdefault(part, {})
        target[key] = value
    return result


def _nested(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current


def _path(value: Any, root: Path, default: Optional[Path] = None) -> Optional[Path]:
    if value is None or value == "":
        return default
    path = Path(os.path.expanduser(str(value)))
    if not path.is_absolute():
        path = root / path
    return path


@dataclass
class Config:
    root: Path
    timezone: str = "Asia/Tokyo"
    daily_hour: int = 5
    daily_minute: int = 0
    lookback_days: int = 1
    drive_sync_path: Optional[Path] = None
    gmail_export_path: Optional[Path] = None
    drive_source_path: Optional[Path] = None
    screenpipe_capture_path: Optional[Path] = None
    line_capture_path: Optional[Path] = None
    discord_capture_path: Optional[Path] = None
    x_capture_path: Optional[Path] = None
    slack_capture_path: Optional[Path] = None
    send_intents_path: Optional[Path] = None
    x_handle: str = "example_user"
    slack_workspace_allowlist: Tuple[str, ...] = ()
    school_workspaces: Tuple[str, ...] = ("example-school.slack.com",)
    discord_reply_allowlist: Tuple[str, ...] = ()
    state_path: Optional[Path] = None
    knowledge_path: Optional[Path] = None
    context_path: Optional[Path] = None
    runs_path: Optional[Path] = None
    reply_queue_path: Optional[Path] = None
    pending_replies_path: Optional[Path] = None
    sync_outputs: bool = False
    # Optional explicit local summarizer hook.  Empty/None keeps the
    # deterministic renderer; no command is run by default.
    summarizer_command: Optional[str] = None
    source_options: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.root = Path(self.root).expanduser().resolve()
        defaults = {
            "drive_sync_path": self.root / "local-sync" / "Life IQ",
            "state_path": self.root / "state" / "ingest-state.json",
            "knowledge_path": self.root / "knowledge",
            "context_path": self.root / "IMPORTANT_CONTEXT.md",
            "runs_path": self.root / "state" / "runs",
            "reply_queue_path": self.root / "state" / "reply-queue.json",
            "pending_replies_path": self.root / "knowledge" / "replies" / "pending.md",
            "line_capture_path": self.root / "captures" / "line" / "live.jsonl",
            "slack_capture_path": self.root / "captures" / "slack" / "live.jsonl",
            "x_capture_path": self.root / "captures" / "x" / "live.jsonl",
            "discord_capture_path": self.root / "captures" / "discord" / "live.jsonl",
            "send_intents_path": self.root / "state" / "send-intents",
        }
        for attr, default in defaults.items():
            if getattr(self, attr) is None:
                setattr(self, attr, default)
        if self.drive_source_path is None:
            self.drive_source_path = self.drive_sync_path

    @classmethod
    def default(cls, root: Optional[Path] = None) -> "Config":
        if root is None:
            root = Path(__file__).resolve().parents[2]
        return cls(root=Path(root))

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any], root: Optional[Path] = None) -> "Config":
        paths = mapping.get("paths", {}) if isinstance(mapping.get("paths", {}), Mapping) else {}
        run = mapping.get("run", {}) if isinstance(mapping.get("run", {}), Mapping) else {}
        sources = mapping.get("sources", {}) if isinstance(mapping.get("sources", {}), Mapping) else {}
        x_options = sources.get("x", {}) if isinstance(sources.get("x", {}), Mapping) else {}
        slack_options = sources.get("slack", {}) if isinstance(sources.get("slack", {}), Mapping) else {}
        discord_options = sources.get("discord", {}) if isinstance(sources.get("discord", {}), Mapping) else {}
        allowlist = slack_options.get("workspace_allowlist", slack_options.get("allowlist", sources.get("slack_workspace_allowlist", ())))
        school_workspaces = slack_options.get("school_workspaces", sources.get("school_workspaces", ("example-school.slack.com",)))
        if isinstance(allowlist, str):
            allowlist = [allowlist]
        if isinstance(school_workspaces, str):
            school_workspaces = [school_workspaces]
        discord_allowlist = discord_options.get("reply_allowlist", sources.get("discord_reply_allowlist", ()))
        if isinstance(discord_allowlist, str):
            discord_allowlist = [discord_allowlist]
        root_value = root or _path(paths.get("root"), Path.cwd(), default=Path.cwd()) or Path.cwd()
        root_path = Path(root_value).expanduser()
        if not root_path.is_absolute():
            root_path = Path.cwd() / root_path
        root_path = root_path.resolve()
        return cls(
            root=root_path,
            timezone=str(run.get("timezone", mapping.get("timezone", "Asia/Tokyo"))),
            daily_hour=int(run.get("daily_hour", 5)),
            daily_minute=int(run.get("daily_minute", 0)),
            lookback_days=int(run.get("lookback_days", 1)),
            drive_sync_path=_path(paths.get("drive_sync"), root_path),
            gmail_export_path=_path(paths.get("gmail_export"), root_path),
            drive_source_path=_path(paths.get("drive_source"), root_path),
            screenpipe_capture_path=_path(paths.get("screenpipe_capture"), root_path),
            line_capture_path=_path(paths.get("line_capture"), root_path),
            discord_capture_path=_path(paths.get("discord_capture"), root_path),
            x_capture_path=_path(paths.get("x_capture"), root_path),
            slack_capture_path=_path(paths.get("slack_capture"), root_path),
            send_intents_path=_path(paths.get("send_intents"), root_path),
            x_handle=str(x_options.get("handle", sources.get("x_handle", "example_user"))).lstrip("@"),
            slack_workspace_allowlist=tuple(str(item) for item in (allowlist or ()) if str(item).strip()),
            school_workspaces=tuple(str(item) for item in (school_workspaces or ()) if str(item).strip()),
            discord_reply_allowlist=tuple(str(item) for item in (discord_allowlist or ()) if str(item).strip()),
            state_path=_path(paths.get("state"), root_path),
            knowledge_path=_path(paths.get("knowledge"), root_path),
            context_path=_path(paths.get("context"), root_path),
            runs_path=_path(paths.get("runs"), root_path),
            reply_queue_path=_path(paths.get("reply_queue"), root_path),
            pending_replies_path=_path(paths.get("pending_replies"), root_path),
            sync_outputs=bool(mapping.get("sync_outputs", paths.get("sync_outputs", False))),
            summarizer_command=(str(run.get("summarizer_command")) if run.get("summarizer_command") else None),
            source_options=dict(sources),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError("cannot read config: %s" % exc)
        try:
            data = json.loads(text) if path.suffix.lower() == ".json" else _parse_simple_toml(text)
        except (ValueError, TypeError) as exc:
            raise ConfigError("cannot parse config: %s" % exc)
        config = cls.from_mapping(data, root=path.parent.parent if path.parent.name == "config" else path.parent)
        errors = config.validate()
        if errors:
            raise ConfigError("; ".join(errors))
        return config

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.root.exists():
            # The root is created by the CLI, so a missing root is a warning in
            # practice, but keeping it in validation makes bad paths visible.
            try:
                self.root.mkdir(parents=True, exist_ok=True)
            except OSError:
                errors.append("root is not writable: %s" % self.root)
        if not re.match(r"^[A-Za-z_]+/[A-Za-z_]+$", self.timezone):
            errors.append("timezone must look like Area/Location")
        if not 0 <= self.daily_hour <= 23:
            errors.append("daily_hour must be between 0 and 23")
        if not 0 <= self.daily_minute <= 59:
            errors.append("daily_minute must be between 0 and 59")
        if self.lookback_days < 1 or self.lookback_days > 365:
            errors.append("lookback_days must be between 1 and 365")
        if self.summarizer_command and re.search(r"(?i)(?:token|password|secret|api[_ -]?key)\s*=", self.summarizer_command):
            errors.append("summarizer_command must not contain credential literals")
        for attr in ("state_path", "knowledge_path", "context_path", "runs_path", "reply_queue_path", "pending_replies_path", "send_intents_path"):
            value = getattr(self, attr)
            if value is None:
                errors.append("%s is not configured" % attr)
        # A source path may be absent until the relevant app/export is set up;
        # that is intentionally not a validation error.
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": str(self.root),
            "timezone": self.timezone,
            "daily_hour": self.daily_hour,
            "daily_minute": self.daily_minute,
            "lookback_days": self.lookback_days,
            "drive_sync_path": str(self.drive_sync_path) if self.drive_sync_path else None,
            "gmail_export_path": str(self.gmail_export_path) if self.gmail_export_path else None,
            "drive_source_path": str(self.drive_source_path) if self.drive_source_path else None,
            "screenpipe_capture_path": str(self.screenpipe_capture_path) if self.screenpipe_capture_path else None,
            "line_capture_path": str(self.line_capture_path) if self.line_capture_path else None,
            "discord_capture_path": str(self.discord_capture_path) if self.discord_capture_path else None,
            "x_capture_path": str(self.x_capture_path) if self.x_capture_path else None,
            "slack_capture_path": str(self.slack_capture_path) if self.slack_capture_path else None,
            "send_intents_path": str(self.send_intents_path) if self.send_intents_path else None,
            "x_handle": self.x_handle,
            "slack_workspace_allowlist": list(self.slack_workspace_allowlist),
            "school_workspaces": list(self.school_workspaces),
            "discord_reply_allowlist": list(self.discord_reply_allowlist),
            "state_path": str(self.state_path) if self.state_path else None,
            "knowledge_path": str(self.knowledge_path) if self.knowledge_path else None,
            "context_path": str(self.context_path) if self.context_path else None,
            "runs_path": str(self.runs_path) if self.runs_path else None,
            "reply_queue_path": str(self.reply_queue_path) if self.reply_queue_path else None,
            "pending_replies_path": str(self.pending_replies_path) if self.pending_replies_path else None,
            "sync_outputs": self.sync_outputs,
            "summarizer_command": self.summarizer_command,
        }


def validate_config(config: Config) -> List[str]:
    return config.validate()


def load_config(path: Optional[Path] = None, root: Optional[Path] = None) -> Config:
    if path is None:
        return Config.default(root=root)
    return Config.from_file(Path(path))
