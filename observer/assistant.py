"""Ask Claude about the lab, watch it work in the wall, and approve any change it wants to make.

A run is one conversation. Claude reaches the lab only through the audited tools below: each
call is recorded with its input, the account or command it used, the time, and the exact text
returned to the model, so the owner can inspect everything that left this workstation.
Credentials never reach the model, search results drop raw event text, and a tool that changes
the lab waits for the owner to approve a stated reason, expected effect, and cleanup.

The Anthropic SDK is optional: without it (or without an API key) the rest of the observer runs.
"""

import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Literal

from observer.store import utc_now

try:
    import anthropic
    from anthropic import beta_tool
    from anthropic.lib.tools import ToolError
except ImportError:  # the observer itself needs only the standard library
    anthropic = None

MODEL = "claude-opus-5-5"
EFFORT = "medium"
MAX_TOKENS = 16000
MAX_ITERATIONS = 40
APPROVAL_TIMEOUT_SECONDS = 15 * 60
RESULT_LIMIT = 12000
FALLBACK_BETA = "server-side-fallback-2026-07-01"
REST_PATH = re.compile(r"^/services(NS/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?/[A-Za-z0-9_/.:-]+$")
# Search results and stored secrets are never read through the REST tool.
REST_BLOCKED = re.compile(r"/search/jobs|/storage/passwords|/search/v2/jobs", re.I)
# A search must reduce events to aggregates so raw event text stays on this workstation.
TRANSFORMING = re.compile(r"(^\s*\|\s*(tstats|mstats|rest|metadata|eventcount|dbinspect|inputlookup|mcatalog))|"
                          r"\|\s*(stats|tstats|chart|timechart|top|rare|eventcount|dbinspect|mstats|sistats|geostats)\b", re.I)
SECRET_TEXT = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|pass4symmkey)(\"?\s*[:=]\s*)\S+")

SYSTEM = """You are the lab assistant inside Splunk Lab Observer, a web interface the lab owner uses to watch every \
component of a Splunk lab running in rootless Podman on one mini PC. The owner sees a wall of Splunk Web screens and \
consoles next to this conversation.

How to work:
- Investigate with the read-only tools freely. Start with lab_overview when you do not yet know the components.
- The owner is watching. Whenever a Splunk Web screen or console would show what you are looking at or about to \
change, call show_screen so it opens in the owner's view, and say in one line what they should see there. Prefer \
screens from list_screens.
- Tie every claim about lab state to evidence from a tool result in this run: name the component, the source \
(REST path, search, podman command or observation id) and the time it was checked. If no tool result supports a \
claim, label it "Unverified:" and say what would verify it.
- Changing the lab (container_action) needs the owner's approval for each call. Before asking, state the plan in \
the conversation; in the call give a specific reason, the expected effect, and the cleanup that restores the \
previous state. If the owner declines, do not retry the same change; ask what they want instead. After an approved \
change, check its effect with the read-only tools and show it.
- Searches must aggregate (stats, timechart, tstats, top and similar); raw events are not available to you.
- Keep answers short and concrete. Use plain text with short lists; no tables wider than four columns."""


def _clip(text, limit=RESULT_LIMIT):
    return text if len(text) <= limit else text[:limit] + f"\n… ({len(text) - limit} more characters not sent)"


def _without_raw(value):
    """Drop raw event text (_raw and friends) from a REST or search payload."""
    if isinstance(value, dict):
        return {key: _without_raw(item) for key, item in value.items() if not key.startswith("_raw")}
    if isinstance(value, list):
        return [_without_raw(item) for item in value]
    return value


class ApiKey:
    """The owner's Anthropic API key: a mode-600 file in the observer's config directory, or the environment."""

    def __init__(self, config_dir):
        self.path = Path(config_dir) / "anthropic.json"

    def value(self):
        if self.path.exists():
            if self.path.stat().st_mode & 0o077:
                raise ValueError("The Anthropic key file must be private to its owner")
            return json.loads(self.path.read_text(encoding="utf-8")).get("api_key") or None
        return os.environ.get("ANTHROPIC_API_KEY") or None

    def status(self):
        try:
            value = self.value()
        except (OSError, ValueError) as error:
            return {"configured": False, "error": str(error)}
        source = "observer settings" if self.path.exists() else ("ANTHROPIC_API_KEY" if value else None)
        return {"configured": bool(value), "source": source, "hint": f"…{value[-4:]}" if value else None}

    def save(self, value):
        value = (value or "").strip()
        if not value:
            self.path.unlink(missing_ok=True)
            return
        if len(value) < 20 or len(value) > 400 or any(char.isspace() for char in value):
            raise ValueError("That does not look like an Anthropic API key")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(self.path.with_suffix(".tmp"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"api_key": value, "saved_at": utc_now()}, handle)
        os.replace(self.path.with_suffix(".tmp"), self.path)


class Run:
    """One conversation: its trail of steps, the model-bound history, and pending approvals."""

    def __init__(self, store, prompt, run_id=None, record=None):
        self.store = store
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.approvals = {}  # approval id -> (threading.Event, decision dict)
        if record:
            self.record = record
        else:
            self.record = {"id": run_id or secrets.token_hex(6), "created_at": utc_now(), "title": prompt.strip()[:120],
                           "status": "running", "model": MODEL, "events": [], "messages": [], "changes": [],
                           "accounts": []}

    @property
    def id(self):
        return self.record["id"]

    def event(self, kind, **fields):
        with self.lock:
            self.record["rev"] = self.record.get("rev", 0) + 1
            item = {"seq": len(self.record["events"]) + 1, "rev": self.record["rev"], "at": utc_now(), "type": kind, **fields}
            self.record["events"].append(item)
        self.save()
        return item

    def update_event(self, seq, **fields):
        with self.lock:
            self.record["rev"] = self.record.get("rev", 0) + 1
            self.record["events"][seq - 1].update(fields, rev=self.record["rev"])
        self.save()

    def set_status(self, status):
        with self.lock:
            self.record["rev"] = self.record.get("rev", 0) + 1
            self.record["status"] = status
        self.save()

    def save(self):
        with self.lock:
            snapshot = json.loads(json.dumps(self.record, default=str))
        self.store.save_run(snapshot)

    def uses(self, account):
        if account not in self.record["accounts"]:
            self.record["accounts"].append(account)

    def view(self, since=0):
        """The run without its model-bound history; events added or changed after revision `since`."""
        with self.lock:
            return json.loads(json.dumps({key: value for key, value in self.record.items() if key != "messages"} | {
                "events": [item for item in self.record["events"] if item["rev"] > since]}, default=str))

    # --- approvals ------------------------------------------------------------------

    def ask_approval(self, action, details):
        approval_id = secrets.token_hex(4)
        waiter = threading.Event()
        decision = {}
        self.approvals[approval_id] = (waiter, decision)
        item = self.event("approval", approval_id=approval_id, action=action, details=details, decision="pending")
        self.set_status("waiting_for_approval")
        deadline = time.time() + APPROVAL_TIMEOUT_SECONDS
        while not waiter.is_set() and not self.cancel.is_set() and time.time() < deadline:
            waiter.wait(1)
        self.approvals.pop(approval_id, None)
        if self.cancel.is_set():
            decision = {"decision": "stopped"}
        elif not waiter.is_set():
            decision = {"decision": "expired"}
        self.update_event(item["seq"], decision=decision["decision"], note=decision.get("note"), decided_at=utc_now())
        self.set_status("running")
        return decision

    def decide(self, approval_id, decision, note=None):
        pending = self.approvals.get(approval_id)
        if pending is None or decision not in {"approve", "deny"}:
            return False
        pending[1].update({"decision": "approved" if decision == "approve" else "declined", "note": (note or "")[:500] or None})
        pending[0].set()
        return True


class Assistant:
    def __init__(self, lab, store, config_dir, monitor=None):
        self.lab = lab
        self.store = store
        self.monitor = monitor
        self.key = ApiKey(config_dir)
        self.runs = {}  # live runs; finished runs are read back from the store
        self.lock = threading.Lock()

    def status(self):
        return {"sdk_available": anthropic is not None, "model": MODEL, "effort": EFFORT, **self.key.status(),
                "read_account": getattr(self.lab.source, "username", None),
                "change_tools": ["container_action (podman start, stop, restart), each approved by you"]}

    def get(self, run_id):
        with self.lock:
            run = self.runs.get(run_id)
        if run:
            return run
        record = self.store.run(run_id)
        return Run(self.store, "", record=record) if record else None

    def start(self, prompt, run_id=None):
        """Start a run, or continue a finished one with a follow-up prompt."""
        if anthropic is None:
            raise RuntimeError("The anthropic package is not installed in the observer's Python")
        if not self.key.value():
            raise RuntimeError("Add an Anthropic API key first")
        prompt = prompt.strip()
        if not prompt or len(prompt) > 8000:
            raise ValueError("Write a prompt of up to 8000 characters")
        with self.lock:
            if run_id:
                run = self.runs.get(run_id) or self.get(run_id)
                if run is None:
                    raise KeyError(run_id)
                if run.record["status"] in {"running", "waiting_for_approval"}:
                    raise RuntimeError("This run is still working")
                run.cancel.clear()
            else:
                run = Run(self.store, prompt)
            self.runs[run.id] = run
        run.record["messages"].append({"role": "user", "content": prompt})
        run.event("prompt", text=prompt)
        run.set_status("running")
        threading.Thread(target=self._work, args=(run,), name=f"assistant-{run.id}", daemon=True).start()
        return run

    def stop(self, run_id):
        run = self.runs.get(run_id)
        if run is None:
            return False
        run.cancel.set()
        return True

    # --- the loop -------------------------------------------------------------------

    def _work(self, run):
        try:
            client = anthropic.Anthropic(api_key=self.key.value())
            runner = client.beta.messages.tool_runner(
                model=MODEL, max_tokens=MAX_TOKENS, system=SYSTEM, tools=self._tools(run),
                messages=list(run.record["messages"]), thread=False, max_iterations=MAX_ITERATIONS,
                thinking={"type": "adaptive", "display": "summarized"}, output_config={"effort": EFFORT},
                betas=[FALLBACK_BETA], fallbacks="default")
            history = run.record["messages"]
            for message in runner:
                content = message.to_dict()["content"]
                self._record_message(run, message)
                if message.stop_reason in {"refusal", "max_tokens"} or run.cancel.is_set():
                    # A cut-off or declined turn's tool calls never run, and it stays out of the history.
                    if message.stop_reason == "refusal":
                        details = message.stop_details.explanation if message.stop_details else None
                        run.event("error", text="Claude declined this request." + (f" {details}" if details else ""))
                    elif message.stop_reason == "max_tokens":
                        run.event("error", text="Claude's reply hit the output limit before it finished.")
                    break
                history.append({"role": "assistant", "content": content})
                response = runner.generate_tool_call_response()
                if response is not None:
                    history.append(json.loads(json.dumps(response, default=str)))
                if run.cancel.is_set():
                    break
            self._finish(run, "stopped" if run.cancel.is_set() else "done")
        except Exception as error:  # report every failure in the trail, never the key
            text = f"{error.__class__.__name__}: {getattr(error, 'message', None) or error}"
            run.event("error", text=_clip(text, 600))
            self._finish(run, "failed")

    def _record_message(self, run, message):
        usage = message.usage
        for block in message.content:
            if block.type == "thinking" and block.thinking:
                run.event("thinking", text=block.thinking)
            elif block.type == "text" and block.text.strip():
                run.event("text", text=block.text)
            elif block.type == "fallback":
                run.event("note", text=f"{block.from_.model} declined; {block.to.model} continued.")
        run.event("usage", model=message.model, input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
                  stop_reason=message.stop_reason, request_id=getattr(message, "_request_id", None))

    def _finish(self, run, status):
        unresolved = []
        try:
            states = {item["name"]: item["state"] for item in self.lab.source.containers()}
            for change in run.record["changes"]:
                if change["action"] == "stop" and states.get(change["component"]) != "running":
                    unresolved.append(f"{change['component']} is still stopped (cleanup: {change['cleanup']})")
        except Exception:  # the summary is best-effort; the trail already holds each change
            pass
        if run.record["changes"]:
            run.event("summary", changes=run.record["changes"], unresolved=unresolved)
        run.set_status(status)

    # --- audited tools --------------------------------------------------------------

    def _call(self, run, name, arguments, source, work):
        """Run one tool, recording its input, source, time, and the exact text returned to the model."""
        if run.cancel.is_set():
            raise ToolError("The owner stopped this run.")
        item = run.event("tool", name=name, input=arguments, source=source, status="running")
        started = time.time()
        try:
            result = work()
            text = _clip(result if isinstance(result, str) else json.dumps(result, default=str, separators=(",", ":")))
            run.update_event(item["seq"], status="ok", result=text, seconds=round(time.time() - started, 2))
            return text
        except ToolError as error:
            run.update_event(item["seq"], status="error", result=str(error.content), seconds=round(time.time() - started, 2))
            raise
        except urllib.error.HTTPError as error:
            message = f"HTTP {error.code} from {source}"
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            message = f"{error.__class__.__name__}: {error}"[:500]
        run.update_event(item["seq"], status="error", result=message, seconds=round(time.time() - started, 2))
        raise ToolError(message)

    def _component(self, component, web=False):
        found = self.lab.component(component)
        if found is None:
            raise ValueError(f"No lab component named {component!r}; call lab_overview for the list")
        if web and not found["web_path"]:
            raise ValueError(f"{component} has no Splunk Web")
        return found

    def _tools(self, run):
        lab, store, source = self.lab, self.store, self.lab.source
        account = getattr(source, "username", "lab_observer")

        @beta_tool
        def lab_overview() -> str:
            """List every lab component with its kind, state, Splunk health, roles and version, plus clusters and
            relationships. Call this first when you do not yet know which components exist."""
            def work():
                snapshot = lab.snapshot()
                components = []
                for item in snapshot["components"]:
                    health = store.latest(item["id"], "splunk_health")
                    container = store.latest(item["id"], "container")
                    components.append({
                        "id": item["id"], "owner_name": item["owner_name"], "kind": item["kind"],
                        "state": container["value"].get("state") if container else item["facts"]["container_state"]["value"],
                        "splunk_health": health["value"].get("health") if health else None,
                        "roles": (item["facts"].get("server_roles") or {}).get("value"),
                        "version": (item["facts"].get("splunk_version") or {}).get("value"),
                        "has_splunk_web": bool(item["web_path"]), "screens": len(item["screens"])})
                return {"checked_at": snapshot["checked_at"], "components": components, "groups": snapshot["groups"],
                        "relationships": [{key: rel.get(key) for key in ("from", "type", "to", "detail")}
                                          for rel in snapshot["relationships"]]}
            return self._call(run, "lab_overview", {}, "observer registry (podman ps + splunkd REST discovery)", work)

        @beta_tool
        def component_status(component: str) -> str:
            """Discovered facts, the latest recorded observations (container, resources, web, Splunk health and
            messages, each with its observation id and time) and recent state changes for one component.

            Args:
                component: Component id from lab_overview, e.g. p-hq-sh1.
            """
            def work():
                found = self._component(component)
                latest = {kind: store.latest(component, kind)
                          for kind in ("container", "resources", "web", "splunk_health", "splunk_messages")}
                return {"facts": {key: value for key, value in found["facts"].items() if key != "installed_apps"},
                        "installed_apps": [f"{app['app']} {app['version'] or ''}".strip() for app in
                                           (found["facts"].get("installed_apps") or {}).get("value", []) if app["visible"]],
                        "latest_observations": latest, "recent_changes": store.changes(component, limit=20)}
            return self._call(run, "component_status", {"component": component}, "observer store", work)

        @beta_tool
        def list_screens(component: str, filter: str = "") -> str:
            """Splunk Web screens of one instance (app navigation menus and built-in Settings pages), with the path
            show_screen takes. Call before show_screen when you need a specific app page.

            Args:
                component: Component id with Splunk Web.
                filter: Optional case-insensitive text to match against app, group and screen labels.
            """
            def work():
                found = self._component(component, web=True)
                term = filter.lower().strip()
                screens = [{"app": item["app_label"], "group": item["group"], "label": item["label"], "path": item["path"]}
                           for item in found["screens"]
                           if not term or term in f"{item['app_label']} {item['group'] or ''} {item['label']}".lower()]
                return {"component": component, "count": len(screens), "screens": screens[:80]}
            return self._call(run, "list_screens", {"component": component, "filter": filter},
                              "installed apps' navigation menus", work)

        @beta_tool
        def show_screen(component: str, path: str = "") -> str:
            """Open a component in the owner's view: a Splunk Web page for Splunk instances, or the container console
            for others. Use it whenever a screen would show the owner what you are describing or changing.

            Args:
                component: Component id.
                path: Splunk Web path starting with /en-US/ (from list_screens). Empty for the instance's home page.
            """
            def work():
                found = self._component(component)
                if path and (not found["web_path"] or not path.startswith("/en-US/") or ".." in path or "//" in path):
                    raise ValueError("path must be a Splunk Web path starting with /en-US/ on an instance with Splunk Web")
                target = path or ("/en-US/app/launcher/home" if found["web_path"] else "")
                run.event("display", component=component, path=target)
                return f"Showing {component}{' ' + target if target else ' console'} to the owner."
            return self._call(run, "show_screen", {"component": component, "path": path}, "observer view", work)

        @beta_tool
        def splunk_rest_get(component: str, path: str, query: str = "") -> str:
            """GET a splunkd REST endpoint on one instance as the read-only lab_observer account, as JSON. Raw event
            text and stored secrets are not readable this way. Use for configuration and status, e.g.
            /services/server/info, /services/cluster/manager/peers, /services/shcluster/status,
            /services/data/indexes, /services/apps/local.

            Args:
                component: Component id of a Splunk Enterprise instance.
                path: REST path starting with /services/ or /servicesNS/<user>/<app>/.
                query: Optional URL query parameters such as "search=name%3Dmain" or "f=title".
            """
            def work():
                found = self._component(component)
                if found["kind"] != "splunk_enterprise":
                    raise ValueError(f"{component} is not a Splunk Enterprise instance")
                if not REST_PATH.match(path) or REST_BLOCKED.search(path) or ".." in path:
                    raise ValueError("Use a /services/ path; search results and stored passwords are not available")
                params = {key: values[-1] for key, values in urllib.parse.parse_qs(query).items()}
                payload, _origin = source.splunk_get(component, path, **params)
                entries = [{"name": entry.get("name"), "content": entry.get("content")} for entry in payload.get("entry", [])]
                return _without_raw({"entries": entries[:100], "total": len(entries)})
            run.uses(account)
            return self._call(run, "splunk_rest_get", {"component": component, "path": path, "query": query},
                              f"splunkd {component}{path} as {account}", work)

        @beta_tool
        def run_search(component: str, query: str, earliest: str = "-60m", latest: str = "now") -> str:
            """Run a Splunk search on one instance as the read-only lab_observer account and return up to 50 result
            rows. The search must aggregate (stats, timechart, tstats, top, ...); raw events are not returned. The
            account sees the indexes Splunk's user role allows.

            Args:
                component: Component id of a Splunk Enterprise instance (usually a search head).
                query: SPL, e.g. "search index=_internal sourcetype=splunkd log_level=ERROR | stats count by component".
                earliest: Earliest time, e.g. -60m or -24h.
                latest: Latest time, e.g. now.
            """
            def work():
                found = self._component(component)
                if found["kind"] != "splunk_enterprise":
                    raise ValueError(f"{component} is not a Splunk Enterprise instance")
                if not TRANSFORMING.search(query):
                    raise ValueError("The search must aggregate with a transforming command (stats, timechart, tstats, top, ...)")
                spl = query.strip()
                if not spl.startswith("|") and not spl.lower().startswith("search "):
                    spl = "search " + spl
                rows, _origin = source.splunk_search(component, spl, earliest, latest, 50)
                return _without_raw({"rows": rows[:50], "row_count": len(rows)})
            run.uses(account)
            return self._call(run, "run_search", {"component": component, "query": query, "earliest": earliest,
                                                  "latest": latest}, f"splunkd {component} oneshot search as {account}", work)

        @beta_tool
        def container_logs(component: str, lines: int = 60) -> str:
            """The last lines of a container's console output (podman logs), with anything that looks like a secret
            masked. Useful for forwarders, load balancers and containers that failed to start.

            Args:
                component: Component id.
                lines: Number of lines, 10 to 200.
            """
            def work():
                self._component(component)
                text = source.logs(component, tail=max(10, min(int(lines), 200)))
                return SECRET_TEXT.sub(lambda match: match.group(1) + match.group(3) + "[masked]", text)[-8000:]
            return self._call(run, "container_logs", {"component": component, "lines": lines},
                              f"podman logs --tail {lines} {component}", work)

        @beta_tool
        def recorded_changes(component: str = "", limit: int = 30) -> str:
            """State changes the observer recorded in the background (container state, Splunk health, web, error
            message counts, installed apps), newest first, each with its observation id and time.

            Args:
                component: Optional component id; empty for the whole lab.
                limit: Number of changes, up to 100.
            """
            def work():
                if component:
                    self._component(component)
                return store.changes(component or None, limit=max(1, min(int(limit), 100)))
            return self._call(run, "recorded_changes", {"component": component, "limit": limit}, "observer store", work)

        @beta_tool
        def container_action(component: str, action: Literal["restart", "stop", "start"], reason: str,
                             expected_effect: str, cleanup: str) -> str:
            """Start, stop or restart a lab container. This changes the lab, so the owner must approve each call; it
            waits until they decide. Explain the plan in the conversation first.

            Args:
                component: Component id.
                action: restart, stop or start.
                reason: Why this change is needed, in one or two sentences.
                expected_effect: What the owner should see happen, including any outage.
                cleanup: How to return the lab to its previous state afterwards (or "none needed" for a restart).
            """
            arguments = {"component": component, "action": action, "reason": reason,
                         "expected_effect": expected_effect, "cleanup": cleanup}

            def work():
                found = self._component(component)
                if found["kind"] == "observer_router":
                    raise ValueError("The observer router serves this interface and cannot be changed from it")
                decision = run.ask_approval(f"podman {action} {component}", arguments)
                if decision["decision"] != "approved":
                    reply = {"declined": "The owner declined this change.", "expired": "No decision within 15 minutes.",
                             "stopped": "The owner stopped this run."}[decision["decision"]]
                    raise ToolError(reply + (f" Owner's note: {decision['note']}" if decision.get("note") else ""))
                before = {item["name"]: item["state"] for item in source.containers()}.get(component)
                started = utc_now()
                source.container_action(component, action)
                after = {item["name"]: item["state"] for item in source.containers()}.get(component)
                change = {"component": component, "action": action, "at": started, "before": before, "after": after,
                          "cleanup": cleanup, "reason": reason}
                run.record["changes"].append(change)
                store.record(component, "assistant_action", f"podman {action} (approved by the owner, run {run.id})", change)
                if self.monitor:  # refresh the wall's status soon instead of at the next minute
                    threading.Thread(target=self.monitor.collect, daemon=True).start()
                return {"done": f"podman {action} {component}", "state_before": before, "state_after": after,
                        "note": "Splunk can take one to three minutes to serve requests after a start or restart."}
            return self._call(run, "container_action", arguments, f"podman {action} {component} (owner approval)", work)

        return [lab_overview, component_status, list_screens, show_screen, splunk_rest_get, run_search,
                container_logs, recorded_changes, container_action]
