# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from .capture import CaptureBridge, CaptureImportError, capture_paths_from_config
from .config import ConfigError, load_config
from .pipeline import LifeIQPipeline
from .pipeline import previous_day_window
from .replies import QueueTransitionError, ReplyCandidateBuilder, ReplyQueue
from .send_intents import SendIntentError, list_send_intents, materialize_send_intent
from .sources.base import SourceWindow
from .sources.discord import DiscordAdapter
from .sources.drive import DriveAdapter
from .sources.gmail import GmailAdapter
from .sources.line import LineAdapter
from .sources.screenpipe import ScreenpipeAdapter
from .sources.x import XAdapter
from .sources.slack import SlackAdapter


def build_adapters(config):
    return [
        GmailAdapter(config.gmail_export_path),
        DriveAdapter(config.drive_source_path, output_root=config.root),
        ScreenpipeAdapter(config.screenpipe_capture_path),
        LineAdapter(config.line_capture_path),
        DiscordAdapter(config.discord_capture_path),
        XAdapter(config.x_capture_path, handle=config.x_handle),
        SlackAdapter(config.slack_capture_path, workspace_allowlist=config.slack_workspace_allowlist, school_workspaces=config.school_workspaces),
    ]


def prepare_candidates(config):
    """Collect local captures and write candidates without any external action."""

    target = previous_day_window(timezone_name=config.timezone)
    history_window = SourceWindow(target.start - timedelta(days=90), target.end)
    events = []
    for adapter in build_adapters(config):
        # Discord needs its 90-day history to determine reciprocal DM days;
        # all other sources are harmlessly bounded to the same history window.
        try:
            result = adapter.collect(history_window)
        except Exception:
            continue
        events.extend(result.events)
    builder = ReplyCandidateBuilder(discord_server_allowlist=config.discord_reply_allowlist)
    candidates = builder.build(events, discovery_start=target.start, discovery_end=target.end)
    queue = ReplyQueue(config.reply_queue_path, config.pending_replies_path, config.send_intents_path)
    return queue, queue.upsert(candidates)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Life IQ read-only local ingestion")
    parser.add_argument("--config", type=Path, help="TOML or JSON config")
    parser.add_argument("--check-config", action="store_true", help="validate configuration and exit")
    parser.add_argument("--no-weekly", action="store_true")
    parser.add_argument("--local-only", action="store_true", help="disable output mirroring and optional summarizer commands for this run")
    parser.add_argument("--status", choices=("pending", "blocked", "approved", "rejected", "sent"))
    parser.add_argument("--all", action="store_true", help="approve/reject every eligible candidate")
    parser.add_argument("--ui-confirmed", action="store_true", help="confirm a real, successful UI send before mark-sent")
    parser.add_argument("--verified-empty", action="store_true", help="declare that a source was visibly checked and confirmed empty")
    parser.add_argument("command", nargs="?", help="daily run or prepare/list/approve/reject (replies <command> also works)")
    parser.add_argument("candidate_ids", nargs="*")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("configuration error: %s" % exc, file=sys.stderr)
        return 2
    if args.local_only:
        # Per-run override: never change the user's saved sync settings.
        config = replace(config, sync_outputs=False, summarizer_command=None)
    errors = config.validate()
    if errors:
        print("configuration error: %s" % "; ".join(errors), file=sys.stderr)
        return 2
    if args.check_config:
        print(json.dumps(config.to_dict(), ensure_ascii=False, indent=2))
        return 0
    command = args.command
    candidate_ids = list(args.candidate_ids)
    if command in ("capture-import", "capture_import"):
        if len(candidate_ids) > 2:
            parser.error("capture-import takes SOURCE and optional FILE|-")
        if not candidate_ids:
            parser.error("capture-import requires SOURCE and optional FILE|-")
        source = candidate_ids[0]
        input_name = candidate_ids[1] if len(candidate_ids) == 2 else "-"
        bridge = CaptureBridge(config.root, paths=capture_paths_from_config(config))
        try:
            result = bridge.import_stdin(source, verified_empty=args.verified_empty) if input_name == "-" else bridge.import_file(source, Path(input_name), verified_empty=args.verified_empty)
        except CaptureImportError as exc:
            print("capture import error: %s" % exc, file=sys.stderr)
            return 2
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.status in ("success", "verified_empty") else 2
    if command in ("capture-status", "capture_status"):
        if candidate_ids:
            parser.error("capture-status takes no arguments")
        bridge = CaptureBridge(config.root, paths=capture_paths_from_config(config))
        print(json.dumps({"captures": [item.to_dict() for item in bridge.status()]}, ensure_ascii=False, indent=2))
        return 0
    if command == "replies":
        if not candidate_ids:
            parser.error("replies requires prepare, list, approve, or reject")
        command = candidate_ids.pop(0)
    if command in ("send-intent", "send_intent", "materialize-send-intent"):
        if len(candidate_ids) != 1:
            parser.error("send-intent requires one approved candidate id")
        try:
            queue = ReplyQueue(config.reply_queue_path, config.pending_replies_path, config.send_intents_path)
            intent = materialize_send_intent(queue, candidate_ids[0], intent_dir=config.send_intents_path)
        except (QueueTransitionError, SendIntentError) as exc:
            print("send intent error: %s" % exc, file=sys.stderr)
            return 2
        print(json.dumps(intent.to_dict(), ensure_ascii=False, indent=2))
        return 0
    if command in ("send-intents", "send_intents"):
        if candidate_ids:
            parser.error("send-intents takes no candidate ids")
        print(json.dumps({"intents": [item.to_dict() for item in list_send_intents(config.send_intents_path)]}, ensure_ascii=False, indent=2))
        return 0
    if command in ("mark-sent", "mark_sent"):
        if len(candidate_ids) != 1:
            parser.error("mark-sent requires one candidate id")
        if not args.ui_confirmed:
            print("mark-sent requires --ui-confirmed after a successful manual UI send", file=sys.stderr)
            return 2
        try:
            queue = ReplyQueue(config.reply_queue_path, config.pending_replies_path, config.send_intents_path)
            candidate = queue.mark_sent(candidate_ids[0], ui_confirmed=True)
        except QueueTransitionError as exc:
            print("reply queue error: %s" % exc, file=sys.stderr)
            return 2
        print(json.dumps(candidate.to_dict(), ensure_ascii=False, indent=2))
        return 0
    if command in ("prepare", "list", "approve", "reject"):
        try:
            queue = ReplyQueue(config.reply_queue_path, config.pending_replies_path, config.send_intents_path)
            if command == "prepare":
                if candidate_ids:
                    parser.error("prepare takes no candidate ids")
                queue, candidates = prepare_candidates(config)
                print(json.dumps({"candidates": [candidate.to_dict() for candidate in candidates]}, ensure_ascii=False, indent=2))
                return 0
            if command == "list":
                if candidate_ids:
                    parser.error("list takes no candidate ids")
                print(json.dumps({"candidates": [candidate.to_dict() for candidate in queue.list(args.status)]}, ensure_ascii=False, indent=2))
                return 0
            if args.all:
                if candidate_ids:
                    parser.error("--all cannot be combined with candidate ids")
                changed = queue.approve_all() if command == "approve" else [queue.reject(candidate.candidate_id) for candidate in queue.list() if candidate.status in ("pending", "blocked")]
            else:
                if len(candidate_ids) != 1:
                    parser.error("approve/reject requires one candidate id or --all")
                changed = [queue.approve(candidate_ids[0])] if command == "approve" else [queue.reject(candidate_ids[0])]
            payload = []
            for candidate in changed:
                item = candidate.to_dict()
                if command == "approve":
                    item["send_ready"] = queue.send_ready(candidate.candidate_id).to_dict()
                payload.append(item)
            print(json.dumps({"candidates": payload}, ensure_ascii=False, indent=2))
            return 0
        except QueueTransitionError as exc:
            print("reply queue error: %s" % exc, file=sys.stderr)
            return 2
    if command is not None:
        parser.error("unknown command: %s" % command)
    result = LifeIQPipeline(config, build_adapters(config)).run(write_weekly=not args.no_weekly)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0 if result.ok else 1
