"""Show Claude Code's terminal work in the observer: the screens it opens and the steps it takes.

Claude Code runs this on the lab PC while it works on the lab from a terminal conversation. Each
command adds a step to a run in the observer's store; an open observer page follows the live
session, opens each screen in the focused view, and keeps the trail with the in-page runs.

    python -m observer.terminal start "Restart the alpha indexers"
    python -m observer.terminal show p-alpha-cm /en-US/manager/system/clustering
    python -m observer.terminal note "Peers are back; replication factor met."
    python -m observer.terminal did "podman restart p-alpha-idx1" --result "running after 95 s"
    python -m observer.terminal coverage TA-hindsight screen:hindsight_overview normal pass --steps 3 4 \
        --note "Overview lists the 8 forwarders with findings"
    python -m observer.terminal end "All three indexers restarted; cluster healthy."

The owner watches the same Splunk session the work uses: `signin` signs the owner's focused view in
as the lab_operator test account, and `read`, `click`, `type` and `select` are carried out by the
owner's open observer page in that view, each element highlighted. They fail if no page is open.

    python -m observer.terminal signin p-hq-sh1 /en-US/app/federation_pulse_hq/pulse_hq_overview
    python -m observer.terminal read p-hq-sh1
    python -m observer.terminal click p-hq-sh1 e12 --why "Open the Members tab"

Commands never carry credentials; write only what the owner may see.
"""

import argparse
import json
import secrets
import sys
import time
from pathlib import Path

from observer.assistant import PAGE_STALE_SECONDS, PAGE_TIMEOUT_SECONDS, Run, _screen_path
from observer.coverage import CASES, Coverage
from observer.store import DEFAULT_DATA_DIR, Store, utc_now

CURRENT = "terminal-run"  # file in the data directory naming the open session


def current_run(store, data_dir):
    path = Path(data_dir) / CURRENT
    run_id = path.read_text().strip() if path.exists() else None
    record = store.run(run_id) if run_id else None
    if record is None or record["status"] != "running":
        return None
    return Run(store, "", record=record)


def ask_page(store, run, action, payload):
    """Have the owner's open page do one action in its live view; wait for the reading it returns."""
    if time.time() - store.page_watch(run.id)["seen"] > PAGE_STALE_SECONDS:
        # An open page follows a session only once it does something after the page opened, so
        # give a page that was opened during a quiet spell a moment to pick this session up.
        run.save()
        deadline = time.time() + PAGE_STALE_SECONDS
        while time.time() < deadline and time.time() - store.page_watch(run.id)["seen"] > PAGE_STALE_SECONDS:
            time.sleep(0.5)
    if time.time() - store.page_watch(run.id)["seen"] > PAGE_STALE_SECONDS:
        raise RuntimeError("No observer page is following this session, so there is no shared view. "
                           "Ask the owner to open the observer page.")
    request_id = secrets.token_hex(4)
    store.add_page_request(request_id, run.id)
    item = run.event("browser", request_id=request_id, action=action, payload=payload, status="pending")
    deadline = time.time() + PAGE_TIMEOUT_SECONDS
    answer = None
    while time.time() < deadline:
        answer = store.page_request(request_id)
        if answer and answer["status"] == "done":
            break
        time.sleep(0.4)
    if not answer or answer["status"] != "done":
        store.close_page_request(request_id, "expired")
        run.update_event(item["seq"], status="expired")
        raise RuntimeError("The owner's page did not answer within 15 minutes")
    result = answer["result"]
    run.update_event(item["seq"], status="done" if answer["ok"] else "failed", summary=result.get("summary"),
                     done_at=utc_now(), summary_url=_screen_path(result.get("url")))
    if not answer["ok"]:
        raise RuntimeError(result.get("error") or "The page could not do that")
    return result


def format_reading(reading):
    lines = [f"url: {reading.get('url')}", f"title: {reading.get('title')}"]
    if reading.get("account"):
        lines.append(f"signed in as: {reading['account']}")
    if reading.get("omitted"):
        lines.append(f"left out: {reading['omitted']}")
    if reading.get("owner_took_over"):
        lines.append("note: the owner took over the view before this ran")
    if reading.get("login_page"):
        lines.append("note: the view shows the Splunk sign-in page")
    lines.append("elements:")
    lines += [f"  {item['ref']} {item['role']}: {item['label']}" + (f" = {item['value']!r}" if item.get("value") else "")
              for item in reading.get("elements", [])]
    lines += ["text:", reading.get("text", "")]
    return "\n".join(lines)


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
    mark = commands.add_parser("coverage", help="mark a case of an app feature or screen (see the Coverage tab)")
    mark.add_argument("app")
    mark.add_argument("item", help="item id from the coverage map, e.g. screen:hindsight_overview")
    mark.add_argument("case", choices=CASES)
    mark.add_argument("result", choices=["pass", "fail", "unverified", "n/a"])
    mark.add_argument("--steps", type=int, nargs="*", default=[], help="step numbers in this session that show it")
    mark.add_argument("--note", default="")
    mark.add_argument("--config-dir", type=Path, default=Path.home() / ".config" / "splunk-lab-observer")
    signin = commands.add_parser("signin", help="sign the owner's view in as the test account and open a page")
    signin.add_argument("component")
    signin.add_argument("path", nargs="?", default="")
    commands.add_parser("read", help="read the screen in the owner's view").add_argument("component")
    click = commands.add_parser("click", help="click an element (a ref from read) in the owner's view")
    click.add_argument("component")
    click.add_argument("ref")
    click.add_argument("--why", default="")
    type_text = commands.add_parser("type", help="type into a field in the owner's view")
    type_text.add_argument("component")
    type_text.add_argument("ref")
    type_text.add_argument("text")
    type_text.add_argument("--enter", action="store_true")
    type_text.add_argument("--why", default="")
    select = commands.add_parser("select", help="choose an option in the owner's view")
    select.add_argument("component")
    select.add_argument("ref")
    select.add_argument("value")
    select.add_argument("--why", default="")
    upload = commands.add_parser("upload", help="choose a package from the observer's packages folder in a file field")
    upload.add_argument("component")
    upload.add_argument("ref")
    upload.add_argument("file", help="file name in <data dir>/packages, e.g. federation_pulse_spoke-100641.tgz")
    upload.add_argument("--why", default="")
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
    elif args.command == "coverage":
        from observer.lab import Lab, PodmanSplunkSource

        lab = Lab(PodmanSplunkSource(), store)
        lab.discover()  # the installed version picks the source ref the item ids come from
        coverage = Coverage(store, lab, args.config_dir)
        source = coverage.source_for(args.app)
        if source is None:
            print(f"No source is configured for {args.app!r}", file=sys.stderr)
            return 1
        if args.item not in {item["id"] for item in coverage.app_map(source)["items"]}:
            print(f"{args.item!r} is not an item of {args.app}", file=sys.stderr)
            return 1
        known = {item["seq"] for item in run.record["events"]}
        steps = [seq for seq in args.steps if seq in known]
        tested = args.result in {"pass", "fail"}
        stored = coverage.record(args.app, args.item, args.case, "tested" if tested else args.result,
                                 verdict=args.result if tested else None, run_id=run.id, evidence=steps,
                                 note=args.note, by="Claude Code (terminal)")
        result = args.result if stored == "tested" else stored
        run.event("coverage", app=args.app, item=args.item, case=args.case, result=result, evidence_steps=steps,
                  note=args.note)
        if result != args.result:
            print(f"Stored as {result}: pass or fail needs --steps from this session", file=sys.stderr)
    elif args.command in {"signin", "read", "click", "type", "select", "upload"}:
        if args.command == "signin" and args.path and (not args.path.startswith("/en-US/") or ".." in args.path):
            print("path must start with /en-US/", file=sys.stderr)
            return 1
        payload = {"component": args.component, "why": getattr(args, "why", "")}
        payload.update({"signin": {"path": getattr(args, "path", "")}, "click": {"ref": getattr(args, "ref", None)},
                        "type": {"ref": getattr(args, "ref", None), "text": getattr(args, "text", None),
                                 "press_enter": getattr(args, "enter", False)},
                        "select": {"ref": getattr(args, "ref", None), "value": getattr(args, "value", None)},
                        "upload": {"ref": getattr(args, "ref", None), "file": getattr(args, "file", None)}}.get(args.command, {}))
        try:
            reading = ask_page(store, run, args.command, payload)
        except RuntimeError as error:
            print(error, file=sys.stderr)
            return 1
        print(format_reading(reading))
        return 0
    elif args.command == "end":
        if args.summary:
            run.event("text", text=args.summary)
        run.set_status("done")
        (Path(args.data_dir) / CURRENT).unlink(missing_ok=True)
    print(f"{run.id} {utc_now()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
