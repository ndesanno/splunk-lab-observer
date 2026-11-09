"""Show Claude Code's terminal work in the observer: the screens it opens and the steps it takes.

Claude Code runs this on the lab PC while it works on the lab from a terminal conversation. Each
command adds a step to a run in the observer's store; an open observer page follows the live
session, opens each screen in the focused view, and keeps the trail with the in-page runs.

    python -m observer.terminal start "Restart the alpha indexers"
    python -m observer.terminal show p-alpha-cm /en-US/manager/system/clustering
    python -m observer.terminal note "Peers are back; replication factor met."
    python -m observer.terminal did "podman restart p-alpha-idx1" --result "running after 95 s"
    python -m observer.terminal end "All three indexers restarted; cluster healthy."

Commands never carry credentials; write only what the owner may see.
"""

import argparse
import sys
from pathlib import Path

from observer.assistant import Run
from observer.store import DEFAULT_DATA_DIR, Store, utc_now

CURRENT = "terminal-run"  # file in the data directory naming the open session


def current_run(store, data_dir):
    path = Path(data_dir) / CURRENT
    run_id = path.read_text().strip() if path.exists() else None
    record = store.run(run_id) if run_id else None
    if record is None or record["status"] != "running":
        return None
    return Run(store, "", record=record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("start", help="open a session").add_argument("title")
    show = commands.add_parser("show", help="open a component's screen or console in the owner's view")
    show.add_argument("component")
    show.add_argument("path", nargs="?", default="")
    commands.add_parser("note", help="tell the owner something").add_argument("text")
    did = commands.add_parser("did", help="record a command or action and its result")
    did.add_argument("action")
    did.add_argument("--result", default="")
    did.add_argument("--failed", action="store_true")
    commands.add_parser("end", help="close the session").add_argument("summary", nargs="?", default="")
    args = parser.parse_args(argv)

    store = Store(args.data_dir)
    if args.command == "start":
        previous = current_run(store, args.data_dir)
        if previous:
            previous.set_status("done")
        run = Run(store, args.title)
        run.record.update(origin="terminal", model="Claude Code (terminal)")
        run.event("prompt", text=args.title)
        (Path(args.data_dir) / CURRENT).write_text(run.id)
        print(run.id)
        return 0
    run = current_run(store, args.data_dir)
    if run is None:
        print("No open session; run `start` first.", file=sys.stderr)
        return 1
    if args.command == "show":
        known = store.latest(args.component, "container") is not None
        if not known:
            print(f"Unknown component {args.component!r}", file=sys.stderr)
            return 1
        web = store.latest(args.component, "web") is not None
        if args.path and (not web or not args.path.startswith("/en-US/") or ".." in args.path):
            print("path must start with /en-US/ on a component with Splunk Web", file=sys.stderr)
            return 1
        run.event("display", component=args.component, path=args.path or ("/en-US/app/launcher/home" if web else ""))
    elif args.command == "note":
        run.event("text", text=args.text)
    elif args.command == "did":
        run.event("tool", name="Claude Code", input={"action": args.action}, source="terminal on the lab PC",
                  status="error" if args.failed else "ok", result=args.result or None)
    elif args.command == "end":
        if args.summary:
            run.event("text", text=args.summary)
        run.set_status("done")
        (Path(args.data_dir) / CURRENT).unlink(missing_ok=True)
    print(f"{run.id} {utc_now()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
