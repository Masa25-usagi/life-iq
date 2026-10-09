# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Orchestration for a read-only Life IQ run."""

from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Sequence
from zoneinfo import ZoneInfo

from .config import Config
from .dedupe import deduplicate_events
from .replies import ReplyCandidateBuilder, ReplyQueue
from .scoring import score_events
from .schema import NormalizedEvent, parse_datetime
from .sources.base import AdapterResult, SourceAdapter, SourceStatus, SourceWindow
from .state import IngestState
from .writers import ArtifactWriter


class RunResult:
    def __init__(self, *, events: Sequence[NormalizedEvent], statuses: Sequence[SourceStatus], artifacts: Sequence[Path], duplicate_count: int, window: SourceWindow, reply_candidates: Sequence[Any] = ()) -> None:
        self.events = list(events)
        self.statuses = list(statuses)
        self.artifacts = list(artifacts)
        self.duplicate_count = duplicate_count
        self.window = window
        self.reply_candidates = list(reply_candidates)

    @property
    def ok(self) -> bool:
        return all(status.status not in ("failed",) for status in self.statuses)

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "ok": self.ok,
            "events": len(self.events),
            "duplicates": self.duplicate_count,
            "statuses": [status.to_dict() for status in self.statuses],
            "artifacts": [str(path) for path in self.artifacts],
            "reply_candidates": len(self.reply_candidates),
            "window": {"start": self.window.start.isoformat(), "end": self.window.end.isoformat()},
        }


def previous_day_window(run_at: Optional[datetime] = None, timezone_name: str = "Asia/Tokyo") -> SourceWindow:
    zone = ZoneInfo(timezone_name)
    local_run = (run_at or datetime.now(timezone.utc)).astimezone(zone)
    day = local_run.date() - timedelta(days=1)
    start_local = datetime.combine(day, time.min, tzinfo=zone)
    end_local = start_local + timedelta(days=1)
    return SourceWindow(start_local, end_local)


class LifeIQPipeline:
    def __init__(self, config: Config, adapters: Optional[Sequence[SourceAdapter]] = None) -> None:
        self.config = config
        if adapters is None:
            # Imports are local to keep the core package usable without
            # initializing any external connector or UI integration.
            from .sources.discord import DiscordAdapter
            from .sources.drive import DriveAdapter
            from .sources.gmail import GmailAdapter
            from .sources.line import LineAdapter
            from .sources.screenpipe import ScreenpipeAdapter
            from .sources.x import XAdapter
            from .sources.slack import SlackAdapter

            adapters = [
                GmailAdapter(config.gmail_export_path),
                DriveAdapter(config.drive_source_path, output_root=config.root),
                ScreenpipeAdapter(config.screenpipe_capture_path),
                LineAdapter(config.line_capture_path),
                DiscordAdapter(config.discord_capture_path),
                XAdapter(config.x_capture_path, handle=config.x_handle),
                SlackAdapter(config.slack_capture_path, workspace_allowlist=config.slack_workspace_allowlist, school_workspaces=config.school_workspaces),
            ]
        self.adapters = list(adapters)
        self.writer = ArtifactWriter(
            config.root,
            context_path=config.context_path,
            drive_sync_path=config.drive_sync_path,
            sync_outputs=config.sync_outputs,
        )

    def run(self, *, run_at: Optional[datetime] = None, window: Optional[SourceWindow] = None, write_weekly: bool = True) -> RunResult:
        normalized_run_at = parse_datetime(run_at) if run_at is not None else None
        window = window or previous_day_window(normalized_run_at, self.config.timezone)
        state = IngestState.load(self.config.state_path)
        statuses: List[SourceStatus] = []
        candidates: List[NormalizedEvent] = []
        successful: List[AdapterResult] = []
        for adapter in self.adapters:
            try:
                result = adapter.collect(window, state.cursor(adapter.source))
            except Exception as exc:
                result = AdapterResult(status=SourceStatus(adapter.source, "failed", "adapter error: %s" % type(exc).__name__))
            result.status.item_count = len(result.events)
            statuses.append(result.status)
            if result.status.status == "success":
                successful.append(result)
                candidates.extend(result.events)

        deduped = deduplicate_events(candidates, state.processed_hashes)
        generated_at = normalized_run_at or datetime.now(timezone.utc)
        scored = score_events(deduped.events, as_of=window.end)

        # Artifacts are written before state is committed.  If a writer fails,
        # the cursor and hashes remain untouched and the same window is retried.
        artifacts: List[Path] = []
        day = window.start.astimezone(ZoneInfo(self.config.timezone)).date()
        artifacts.append(self.writer.write_daily(day, scored, statuses, generated_at=generated_at))
        if write_weekly:
            week_start = day - timedelta(days=day.weekday())
            artifacts.append(self.writer.write_weekly(week_start, scored, generated_at=generated_at))
        artifacts.append(self.writer.write_context(scored, statuses, generated_at=generated_at, summarizer_command=self.config.summarizer_command))

        # Candidate discovery is part of the same run and has no waiting
        # window.  Discord receives an additional read-only 90-day history
        # sweep solely for reciprocal-DM eligibility; it never traverses a
        # server or mutates read state.
        reply_events = list(candidates)
        history_window = SourceWindow(window.start - timedelta(days=90), window.end)
        for adapter in self.adapters:
            if adapter.source != "discord":
                continue
            try:
                history_result = adapter.collect(history_window, state.cursor(adapter.source))
            except Exception:
                history_result = None
            if history_result is not None:
                reply_events.extend(history_result.events)
        candidate_builder = ReplyCandidateBuilder(discord_server_allowlist=self.config.discord_reply_allowlist, now=generated_at)
        reply_candidates = candidate_builder.build(
            reply_events,
            discovery_start=window.start,
            discovery_end=window.end,
            discovered_at=generated_at,
        )
        reply_queue = ReplyQueue(self.config.reply_queue_path, self.config.pending_replies_path, self.config.send_intents_path)
        reply_queue.upsert(reply_candidates)
        artifacts.extend([self.config.reply_queue_path, self.config.pending_replies_path])

        run_record = {
            "generated_at": parse_datetime(generated_at).isoformat(),
            "window": {"start": window.start.isoformat(), "end": window.end.isoformat()},
            "events": len(scored),
            "duplicates": deduped.duplicate_count,
            "statuses": [status.to_dict() for status in statuses],
        }
        run_path = self.config.runs_path / (parse_datetime(generated_at).strftime("%Y%m%dT%H%M%SZ") + ".json")
        import json
        from .state import _atomic_json_write
        _atomic_json_write(run_path, run_record)

        next_state = state.copy()
        for result in successful:
            next_state.record_success(result.status.source, result.status.cursor, observed_at=generated_at, item_count=len(result.events))
        next_state.add_hashes(event.content_hash for event in scored)
        for status in statuses:
            if status.status != "success":
                next_state.record_status(status.source, status.status, status.diagnostic)
        next_state.save(self.config.state_path)
        return RunResult(events=scored, statuses=statuses, artifacts=artifacts, duplicate_count=deduped.duplicate_count, window=window, reply_candidates=reply_candidates)
