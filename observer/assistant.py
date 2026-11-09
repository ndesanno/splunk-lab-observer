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
# Changes never touch stored secrets or the accounts the observer and the owner sign in with.
CHANGE_BLOCKED = re.compile(r"/storage/passwords|/authentication/users/(admin|lab_operator|lab_observer)\b|"
                            r"/authorization/roles/(admin|lab_observer)\b|/server/control|/authentication/providers", re.I)
# A click on one of these, or on a submit button, may change the lab, so it needs the owner's approval.
RISKY_LABEL = re.compile(r"(?i)\b(save|delete|remove|submit|apply|create|add|new|enable|disable|restart|update|confirm|"
                         r"install|uninstall|upgrade|publish|clone|move|rename|reassign|run|schedule|import|upload|"
                         r"rebalance|rolling|push|reload|ok|yes|accept|activate|deactivate|reset|clear)\b")
RISKY_HREF = re.compile(r"(?i)(delete|disable|enable|remove|restart|_reload|action=)")
PAGE_TIMEOUT_SECONDS = 15 * 60
PAGE_STALE_SECONDS = 15
SECRET_KEYS = re.compile(r"(?i)pass(word)?|secret|token|pass4symmkey|sslpassword")
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
- Changing the lab (container_action, and splunk_change when it is available) needs the owner's approval for \
each call. Before asking, state the plan in \
the conversation; in the call give a specific reason, the expected effect, and the cleanup that restores the \
previous state. If the owner declines, do not retry the same change; ask what they want instead. After an approved \
change, check its effect with the read-only tools and show it.
- Name any test objects you create with a test_fixture_ prefix so they are easy to find and remove, and clean \
them up (with approval) when the test is done.
- To show or test an app workflow in Splunk Web, first propose_walkthrough with short steps and wait for the \
owner to agree. Then work in the owner's live view with read_screen, click, type_text and select_option, and call \
checkpoint after each agreed step. Read the screen again after anything changes. If the view shows Splunk's sign-in \
page, ask the owner to sign in; never type passwords. Clicks that save, delete, enable or submit wait for approval. \
To run a search in Splunk Web, open /en-US/app/search/search?q=<URL-encoded SPL>&earliest=-60m with show_screen \
(the search bar is a code editor that typing cannot drive); raw events on screen are left out of read_screen.
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


def _without_secrets(value):
    """Mask secret-looking values in a splunkd reply before it reaches the model."""
    if isinstance(value, dict):
        return {key: "[masked]" if SECRET_KEYS.search(key) and isinstance(item, str) and item else _without_secrets(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_without_secrets(item) for item in value]
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
        self.page_requests = {}  # request id -> (threading.Event, result dict)
        self.screens = {}  # component -> {ref: element} from the owner's page's last reading
        self.page_seen = 0.0  # last time an observer page polled this run
        if record:
            self.record = record
        else:
            self.record = {"id": run_id or secrets.token_hex(6), "created_at": utc_now(), "title": prompt.strip()[:120],
                           "status": "running", "origin": "api", "model": MODEL, "events": [], "messages": [], "changes": [],
                           "accounts": []}

    @property
    def id(self):
        return self.record["id"]

    def event(self, event_type, **fields):
        with self.lock:
            self.record["rev"] = self.record.get("rev", 0) + 1
            item = {"seq": len(self.record["events"]) + 1, "rev": self.record["rev"], "at": utc_now(), "type": event_type, **fields}
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

    def ask_approval(self, action, details, kind="change"):
        """Wait for the owner's decision on a change, a walkthrough plan, or a checkpoint."""
        approval_id = secrets.token_hex(4)
        waiter = threading.Event()
        decision = {}
        self.approvals[approval_id] = (waiter, decision)
        item = self.event("approval", approval_id=approval_id, kind=kind, action=action, details=details, decision="pending")
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

    def ask_page(self, action, payload):
        """Ask the owner's open observer page to read or act in its live Splunk view, and wait for the result.
        The page holds requests while the owner has paused or taken over."""
        if time.time() - self.page_seen > PAGE_STALE_SECONDS:
            raise RuntimeError("The owner's observer page is not open on this run, so there is no shared view to use")
        request_id = secrets.token_hex(4)
        waiter = threading.Event()
        result = {}
        self.page_requests[request_id] = (waiter, result)
        item = self.event("browser", request_id=request_id, action=action, payload=payload, status="pending")
        deadline = time.time() + PAGE_TIMEOUT_SECONDS
        while not waiter.is_set() and not self.cancel.is_set() and time.time() < deadline:
            waiter.wait(0.5)
        self.page_requests.pop(request_id, None)
        if not waiter.is_set():
            self.update_event(item["seq"], status="stopped" if self.cancel.is_set() else "expired")
            raise RuntimeError("The owner stopped this run" if self.cancel.is_set() else "The owner's page did not answer within 15 minutes")
        self.update_event(item["seq"], status="done" if result.get("ok") else "failed",
                          summary=(result.get("result") or {}).get("summary"), done_at=utc_now())
        if not result.get("ok"):
            raise RuntimeError((result.get("result") or {}).get("error") or "The page could not do that")
        return result["result"]

    def page_result(self, request_id, ok, result):
        pending = self.page_requests.get(request_id)
        if pending is None or pending[0].is_set():
            return False
        pending[1].update({"ok": bool(ok), "result": result if isinstance(result, dict) else {}})
        pending[0].set()
        return True

    def control(self, action):
        """The owner paused, took over, or resumed the AI's use of the shared view."""
        text = {"pause": "You paused Claude's actions in the shared view.",
                "takeover": "You took over the shared view; Claude waits until you hand it back.",
                "resume": "You handed the shared view back to Claude."}.get(action)
        if text is None:
            return False
        self.record["paused"] = action != "resume"
        self.event("control", action=action, text=text)
        return True

    def decide(self, approval_id, decision, note=None):
        pending = self.approvals.get(approval_id)
        if pending is None or decision not in {"approve", "deny"}:
            return False
        pending[1].update({"decision": "approved" if decision == "approve" else "declined", "note": (note or "")[:500] or None})
        pending[0].set()
        return True


class Assistant:
    def __init__(self, lab, store, config_dir, monitor=None, operator=None):
        self.lab = lab
        self.store = store
        self.monitor = monitor
        self.key = ApiKey(config_dir)
        self.operator = operator
        self.runs = {}  # live runs; finished runs are read back from the store
        self.lock = threading.Lock()

    def status(self):
        return {"sdk_available": anthropic is not None, "model": MODEL, "effort": EFFORT, **self.key.status(),
                "read_account": getattr(self.lab.source, "username", None),
                "change_account": self.operator.username if self.operator else None,
                "change_tools": ["container_action (podman start, stop, restart)"] +
                                (["splunk_change (splunkd POST or DELETE as " + self.operator.username + ")"] if self.operator else [])}

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
                run = self.runs.get(run_id)
                if run is None:  # finished before the observer last started
                    record = self.store.run(run_id)
                    run = Run(self.store, "", record=record) if record else None
                if run is None:
                    raise KeyError(run_id)
                if run.record.get("origin") == "terminal":
                    raise RuntimeError("A Claude Code terminal session cannot be continued here; start a new conversation")
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
                if change.get("action") == "stop" and states.get(change["component"]) != "running":
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
        except Exception as error:  # a defect in a tool still ends its step and reaches Claude as an error
            message = f"Tool failed ({error.__class__.__name__}: {error})"[:500]
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
                if path and (not found["web_path"] or not path.startswith("/en-US/") or "//" in path.split("?")[0]
                             or ".." in path.split("?")[0]):
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
                          "cleanup": cleanup, "reason": reason,
                          "description": f"podman {action} {component} ({before} → {after})"}
                run.record["changes"].append(change)
                store.record(component, "assistant_action", f"podman {action} (approved by the owner, run {run.id})", change)
                if self.monitor:  # refresh the wall's status soon instead of at the next minute
                    threading.Thread(target=self.monitor.collect, daemon=True).start()
                return {"done": f"podman {action} {component}", "state_before": before, "state_after": after,
                        "note": "Splunk can take one to three minutes to serve requests after a start or restart."}
            return self._call(run, "container_action", arguments, f"podman {action} {component} (owner approval)", work)

        def screen_reply(component, snapshot):
            """Keep the element map for approval checks and give the model a compact reading."""
            elements = snapshot.get("elements") or []
            run.screens[component] = {item["ref"]: item for item in elements if isinstance(item, dict) and item.get("ref")}
            lines = []
            for item in elements[:150]:
                extra = "".join(f" {key}={item[key]!r}" for key in ("type", "value", "href") if item.get(key))
                lines.append(f"[{item.get('ref')}] {item.get('role')} {item.get('label')!r}{extra}{' (in form)' if item.get('in_form') else ''}")
            reply = {"url": snapshot.get("url"), "title": snapshot.get("title"), "text": _clip(snapshot.get("text") or "", 5000),
                     "elements": lines}
            if snapshot.get("login_page"):
                reply["note"] = "This is Splunk's sign-in page. Ask the owner to sign in in the shared view; never type a password."
            if snapshot.get("owner_took_over"):
                reply["note"] = "The owner took over the view before this step and may have changed the page."
            if snapshot.get("omitted"):
                reply["omitted"] = snapshot["omitted"]
            return reply

        def web_component(component):
            found = self._component(component, web=True)
            return found

        @beta_tool
        def read_screen(component: str) -> str:
            """Read what the owner's live Splunk Web view of a component shows: its URL, visible text, and numbered
            interactive elements ([e12] button 'Save') to use with click, type_text and select_option. Opens the
            component in the owner's view first if needed. Raw event text and password values are left out.

            Args:
                component: Component id with Splunk Web.
            """
            def work():
                web_component(component)
                return screen_reply(component, run.ask_page("read", {"component": component}))
            return self._call(run, "read_screen", {"component": component}, f"owner's live view of {component}", work)

        def guarded(component, ref, action, label_for_approval, why, extra=None):
            element = run.screens.get(component, {}).get(ref)
            if element is None:
                raise ValueError(f"No element {ref} in the last reading of {component}; call read_screen first")
            risky = (action == "click" and (RISKY_LABEL.search(element.get("label") or "") or element.get("type") == "submit"
                                            or RISKY_HREF.search(element.get("href") or ""))) or \
                    (action == "type" and (extra or {}).get("press_enter") and element.get("in_form") and element.get("type") != "search")
            if risky:
                decision = run.ask_approval(f"{label_for_approval} in {component}", {
                    "reason": why, "expected_effect": f"May change the lab: {element.get('role')} {element.get('label')!r}"
                    f" on {(run.screens.get(component) and element.get('page')) or 'the current page'}",
                    "cleanup": (extra or {}).get("cleanup") or "Claude must state how to undo this in the conversation"})
                if decision["decision"] != "approved":
                    raise ToolError({"declined": "The owner declined this action.", "expired": "No decision within 15 minutes.",
                                     "stopped": "The owner stopped this run."}[decision["decision"]] +
                                    (f" Owner's note: {decision['note']}" if decision.get("note") else ""))
            return element

        @beta_tool
        def click(component: str, ref: str, why: str, cleanup: str = "") -> str:
            """Click an element from the last read_screen of a component, in the owner's live view, and return the new
            reading. The owner sees the element highlighted. Clicks on buttons such as Save, Delete, Enable or Apply,
            and on submit buttons, wait for the owner's approval.

            Args:
                component: Component id with Splunk Web.
                ref: Element reference from read_screen, e.g. e12.
                why: What this click does in the workflow, in a few words; shown to the owner.
                cleanup: For a click that changes the lab, how to undo it.
            """
            def work():
                web_component(component)
                element = guarded(component, ref, "click", f"Click {element_label(component, ref)}", why, {"cleanup": cleanup})
                return screen_reply(component, run.ask_page("click", {"component": component, "ref": ref, "why": why,
                                                                        "label": element.get("label")}))
            return self._call(run, "click", {"component": component, "ref": ref, "why": why},
                              f"owner's live view of {component}", work)

        def element_label(component, ref):
            element = run.screens.get(component, {}).get(ref) or {}
            return f"{element.get('role', 'element')} {element.get('label')!r}"

        @beta_tool
        def type_text(component: str, ref: str, text: str, why: str, press_enter: bool = False) -> str:
            """Type into a text field from the last read_screen, in the owner's live view, and return the new reading.
            Never use it for passwords; password fields are refused. Pressing Enter in a form field waits for the
            owner's approval because it can submit the form.

            Args:
                component: Component id with Splunk Web.
                ref: Element reference of the field.
                text: The text to enter (replaces the field's current value).
                why: What this input is for, in a few words; shown to the owner.
                press_enter: Press Enter after typing, e.g. to run a search.
            """
            def work():
                web_component(component)
                element = guarded(component, ref, "type", f"Type into {element_label(component, ref)} and press Enter", why,
                                  {"press_enter": press_enter})
                if element.get("type") == "password":
                    raise ValueError("Password fields are for the owner only")
                return screen_reply(component, run.ask_page("type", {"component": component, "ref": ref, "text": text,
                                                                       "press_enter": press_enter, "why": why,
                                                                       "label": element.get("label")}))
            return self._call(run, "type_text", {"component": component, "ref": ref, "text": text, "why": why,
                                                 "press_enter": press_enter}, f"owner's live view of {component}", work)

        @beta_tool
        def select_option(component: str, ref: str, value: str, why: str) -> str:
            """Choose an option in a dropdown (select element) from the last read_screen, in the owner's live view.

            Args:
                component: Component id with Splunk Web.
                ref: Element reference of the select.
                value: The option's value or visible label.
                why: What this choice is for; shown to the owner.
            """
            def work():
                web_component(component)
                element = guarded(component, ref, "select", f"Select {value!r}", why)
                return screen_reply(component, run.ask_page("select", {"component": component, "ref": ref, "value": value,
                                                                         "why": why, "label": element.get("label")}))
            return self._call(run, "select_option", {"component": component, "ref": ref, "value": value, "why": why},
                              f"owner's live view of {component}", work)

        @beta_tool
        def propose_walkthrough(goal: str, steps: list[str]) -> str:
            """Before guiding the owner through an app workflow in the shared view, propose the steps and wait for the
            owner to agree. Then do the steps in order and call checkpoint after each one.

            Args:
                goal: What the walkthrough shows or tests, in one sentence.
                steps: Short, ordered steps, e.g. ["Open Hindsight Vulnerability Overview", "Filter to critical hosts"].
            """
            arguments = {"goal": goal, "steps": steps}

            def work():
                if not steps or len(steps) > 30:
                    raise ValueError("Give between 1 and 30 steps")
                decision = run.ask_approval(f"Walkthrough: {goal}", {"goal": goal, "steps": steps}, kind="plan")
                run.record["walkthrough"] = {"goal": goal, "steps": steps, "agreed": decision["decision"] == "approved"}
                if decision["decision"] != "approved":
                    raise ToolError("The owner did not start this walkthrough." +
                                    (f" Owner's note: {decision['note']}" if decision.get("note") else ""))
                return {"agreed": True, "note": decision.get("note"), "steps": steps}
            return self._call(run, "propose_walkthrough", arguments, "owner decision", work)

        @beta_tool
        def checkpoint(step_done: str, observed: str, next_step: str = "") -> str:
            """Pause after each agreed walkthrough step until the owner continues. Say what was done and what the screen
            showed, so the owner can compare it with the view.

            Args:
                step_done: The step just completed.
                observed: What the screen showed as the result, with any values that matter.
                next_step: The next agreed step, or empty if the walkthrough is complete.
            """
            arguments = {"step_done": step_done, "observed": observed, "next_step": next_step}

            def work():
                decision = run.ask_approval(f"Step done: {step_done}", arguments, kind="checkpoint")
                if decision["decision"] != "approved":
                    raise ToolError("The owner stopped the walkthrough here." +
                                    (f" Owner's note: {decision['note']}" if decision.get("note") else ""))
                return {"continue": True, "note": decision.get("note")}
            return self._call(run, "checkpoint", arguments, "owner decision", work)

        tools = [lab_overview, component_status, list_screens, show_screen, splunk_rest_get, run_search,
                 container_logs, recorded_changes, container_action, read_screen, click, type_text, select_option,
                 propose_walkthrough, checkpoint]
        operator = self.operator
        if operator is None:
            return tools

        @beta_tool
        def splunk_change(component: str, method: Literal["POST", "DELETE"], path: str, params: dict[str, str],
                          reason: str, expected_effect: str, cleanup: str) -> str:
            """Change Splunk configuration or state through splunkd REST as the lab_operator account (admin role):
            create or edit indexes, saved searches, apps, inputs, roles, cluster settings and similar. The owner must
            approve each call; it waits until they decide. Explain the plan in the conversation first, and read the
            current value with splunk_rest_get so the cleanup can restore it. Stored passwords, the admin and observer
            accounts, and server restart are not available; restart a container with container_action instead.

            Args:
                component: Component id of a Splunk Enterprise instance. For a search head cluster, use one member.
                method: POST to create or edit, DELETE to remove.
                path: REST path starting with /services/ or /servicesNS/<user>/<app>/.
                params: Form fields to send with a POST, e.g. {"name": "test_fixture_idx", "maxTotalDataSizeMB": "100"}.
                    Empty for DELETE.
                reason: Why this change is needed, in one or two sentences.
                expected_effect: What the owner should see change.
                cleanup: The exact change that restores the previous state (method, path and fields).
            """
            arguments = {"component": component, "method": method, "path": path, "params": params, "reason": reason,
                         "expected_effect": expected_effect, "cleanup": cleanup}

            def work():
                found = self._component(component)
                if found["kind"] != "splunk_enterprise":
                    raise ValueError(f"{component} is not a Splunk Enterprise instance")
                if not REST_PATH.match(path) or CHANGE_BLOCKED.search(path) or ".." in path:
                    raise ValueError("Not an allowed change path (stored passwords, the admin and observer accounts, "
                                     "authentication providers and server control are excluded)")
                if not all(isinstance(key, str) and isinstance(value, str) for key, value in (params or {}).items()):
                    raise ValueError("params must map field names to strings")
                decision = run.ask_approval(f"{method} {path} on {component} as {operator.username}", arguments)
                if decision["decision"] != "approved":
                    reply = {"declined": "The owner declined this change.", "expired": "No decision within 15 minutes.",
                             "stopped": "The owner stopped this run."}[decision["decision"]]
                    raise ToolError(reply + (f" Owner's note: {decision['note']}" if decision.get("note") else ""))
                started = utc_now()
                status, reply = operator.request(component, method, path, params or {})
                ok = 200 <= status < 300
                change = {"component": component, "method": method, "path": path, "params": params, "at": started,
                          "http_status": status, "cleanup": cleanup, "reason": reason, "succeeded": ok,
                          "description": f"{method} {path} on {component}: HTTP {status}"}
                if ok:
                    run.record["changes"].append(change)
                store.record(component, "assistant_action",
                             f"splunkd {method} {path} as {operator.username} (approved by the owner, run {run.id})", change)
                body = _without_secrets(_without_raw(reply))
                messages = [item.get("text") for item in body.get("messages", []) if isinstance(item, dict)]
                entries = [{"name": entry.get("name"), "content": entry.get("content")} for entry in body.get("entry", [])][:20]
                if not ok:
                    raise ToolError(f"splunkd answered HTTP {status}: {'; '.join(filter(None, messages)) or body}"[:2000])
                return {"http_status": status, "messages": messages, "entries": entries}
            run.uses(operator.username)
            return self._call(run, "splunk_change", arguments,
                              f"splunkd {method} {component}{path} as {operator.username} (owner approval)", work)

        return tools + [splunk_change]
