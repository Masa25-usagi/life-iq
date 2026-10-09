"""Persistent, content-free retry state for the Life IQ heartbeat."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time

SOURCES = ("line", "discord", "slack", "x", "pipeline")
ERRORS = ("connection", "timeout", "ownership", "ocr", "permission", "login",
          "account", "scope", "window", "local_io", "validation", "interrupted")
# The scheduled task may run under a read-only project sandbox. Keep this small
# health ledger in the user's writable Codex data area instead of the project.
DEFAULT_STATE = Path("/Users/example/Documents/Codex/life-iq-state/patrol-health.json")


def record(state, source, outcome, now):
    previous = state.get(source, {})
    failures = 0 if outcome == "success" else previous.get("failures", 0) + 1
    # One, two, four, then six hours. Permissions/login require human action.
    hours = 0 if not failures else min(6, 2 ** min(failures - 1, 3))
    if outcome in ("permission", "login", "account", "scope"):
        hours = 6
    item = dict(outcome=outcome, failures=failures, updated_at=now,
                next_attempt_at=now + hours * 3600)
    state[source] = item
    return item


def save(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".patrol-health-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(state, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def locked_state(path):
    """Serialize read-modify-write operations across concurrent patrol workers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    with lock_path.open("a+") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    begin = sub.add_parser("begin")
    begin.add_argument("source", choices=SOURCES)
    finish = sub.add_parser("finish")
    finish.add_argument("source", choices=SOURCES)
    finish.add_argument("outcome", choices=("success",) + ERRORS)
    args = parser.parse_args()
    with locked_state(args.state):
        # Malformed state fails closed; never overwrite the evidence with defaults.
        state = json.loads(args.state.read_text()) if args.state.exists() else {}
        if not isinstance(state, dict):
            raise ValueError("Invalid patrol health state")
        now = time.time()
        if args.command == "plan":
            changed = False
            for source, item in list(state.items()):
                if item.get("outcome") == "running" and now - item["updated_at"] >= 3600:
                    record(state, source, "interrupted", now)
                    changed = True
            if changed:
                save(args.state, state)
            print(json.dumps({source: {"due": state.get(source, {}).get("outcome") != "running"
                                      and now >= state.get(source, {}).get("next_attempt_at", 0),
                                      **state.get(source, {})} for source in SOURCES}))
        elif args.command == "begin":
            previous = state.get(args.source, {})
            if previous.get("outcome") == "running" or now < previous.get("next_attempt_at", 0):
                parser.exit(2, "Source is running or cooling down\n")
            state[args.source] = {**previous, "outcome": "running", "updated_at": now}
            save(args.state, state)
        else:
            previous = state.get(args.source, {}).get("outcome")
            record(state, args.source, args.outcome, now)
            save(args.state, state)
            print(json.dumps({"source": args.source, "outcome": args.outcome,
                              "previous": previous, **state[args.source]}))


if __name__ == "__main__":
    main()
