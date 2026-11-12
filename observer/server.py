"""Serve the observer page and a same-origin view of one Splunk component."""

import argparse
import gzip
import hashlib
import http.client
import json
import re
import shutil
import socket
import ssl
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from observer.auth import COOKIE_NAME, SESSION_LIFETIME_SECONDS, OwnerLogin
from observer.setup_lan import DEFAULT_CONFIG_DIR, private_lan_address
from observer.store import utc_now


PAGE = Path(__file__).with_name("view.html")
LOGIN_PAGE = Path(__file__).with_name("login.html")
# Previews are taken every 10 minutes; a gap beyond one and a half intervals counts as missing.
MISSING_CAPTURE_SECONDS = 15 * 60
COMPONENT_PATH = re.compile(r"^/lab/([A-Za-z0-9][A-Za-z0-9_.-]{0,62})/")
COOKIE_ROOT_PATH = re.compile(r"(;\s*path=)/(?=;|$)", re.I)
COMPRESSIBLE = ("text/", "application/json", "application/javascript")
# A browser keeps its connections open between requests; an idle one is dropped after this long.
IDLE_SECONDS = 75
UPSTREAM_TIMEOUT_SECONDS = 60
STALE_UPSTREAM = (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


class ObserverServer(ThreadingHTTPServer):
    daemon_threads = True
    # A Splunk page asks for dozens of files at once and a wall holds several pages.
    request_queue_size = 128

    def __init__(self, address, upstream_url, auth_file=None, certfile=None, keyfile=None, lab=None, store=None, capture=None, monitor=None, assistant=None, coverage=None, checks=None):
        secure_mode = any(item is not None for item in (auth_file, certfile, keyfile))
        if secure_mode and not all(item is not None for item in (auth_file, certfile, keyfile)):
            raise ValueError("LAN mode requires authentication, certificate, and private key files")
        if not secure_mode and address[0] not in {"127.0.0.1", "localhost"}:
            raise ValueError("An HTTP observer must bind to loopback")
        if secure_mode:
            private_lan_address(address[0])
            if Path(keyfile).stat().st_mode & 0o077:
                raise ValueError("The TLS private key must be private to its owner")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(certfile), str(keyfile))
            self.login = OwnerLogin(auth_file)
        else:
            context = None
            self.login = None
        parsed = urlsplit(upstream_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.path not in {"", "/"}:
            raise ValueError("The component router must be an HTTP service on this workstation")
        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port or 80
        self.upstream_origin = f"http://{self.upstream_host}:{self.upstream_port}"
        self.scheme = "https" if secure_mode else "http"
        self.allowed_hosts = {address[0]} if secure_mode else {"127.0.0.1", "localhost"}
        self.lab, self.store, self.capture, self.monitor, self.assistant = lab, store, capture, monitor, assistant
        self.coverage = coverage
        self.checks = checks
        self.tls_context = context
        self.summary_cache = (None, None)  # (store version and background status, summary)
        super().__init__(address, ObserverHandler)

    def process_request_thread(self, request, client_address):
        # Headers and body are written separately; on a kept connection the body would otherwise
        # wait for the browser's delayed acknowledgement of the headers.
        request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # The TLS handshake runs here, in the connection's own thread: on the listening socket it
        # would run in the accept loop, where one slow client holds up every other connection.
        if self.tls_context is not None:
            try:
                request.settimeout(10)
                request = self.tls_context.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError):
                self.shutdown_request(request)
                return
        super().process_request_thread(request, client_address)


class ObserverHandler(BaseHTTPRequestHandler):
    # Connections stay open between requests, so a page's many files do not each pay for a new
    # TCP and TLS handshake. Every response therefore states its length or is sent in chunks.
    protocol_version = "HTTP/1.1"
    timeout = IDLE_SECONDS
    upstream = None

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_PATCH(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def finish(self):
        if self.upstream is not None:
            self.upstream.close()
        super().finish()

    def _route(self):
        self.body_read = False
        try:
            self._dispatch()
        finally:
            if self._body_unread():
                self.close_connection = True

    def _body_unread(self):
        """A request body nobody read would be taken for the next request on this connection."""
        sent = self.headers.get("Content-Length", "0") not in {"", "0"} or "Transfer-Encoding" in self.headers
        return sent and not self.body_read

    def _end_headers(self):
        if self._body_unread():
            self.send_header("Connection", "close")
        self.end_headers()

    def _dispatch(self):
        browser_origin = self._browser_origin()
        if browser_origin is None or not self._same_origin_request(browser_origin):
            self._send(403, b"Request origin not allowed", "text/plain; charset=utf-8")
            return
        if self.server.login and self.path == "/observer/login":
            if self.command == "GET":
                self._send(200, LOGIN_PAGE.read_bytes(), "text/html; charset=utf-8")
            elif self.command == "POST":
                self._login()
            else:
                self._send(405, b"Method not allowed", "text/plain; charset=utf-8")
            return
        if not self._authenticated():
            if self.path.startswith("/observer/api/"):
                self._send(401, b'{"error":"login_required"}', "application/json")
            elif self.command in {"GET", "HEAD"}:
                self._redirect("/observer/login")
            else:
                self._send(401, b"Observer login required", "text/plain; charset=utf-8")
            return
        if self.server.login and self.path == "/observer/logout" and self.command == "POST":
            self.server.login.end_session(self._session_token())
            self._redirect("/observer/login", [
                ("Set-Cookie", f"{COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")
            ])
        elif self.path == "/observer/" and self.command == "GET":
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8", cache="no-cache", revalidate=True)
        elif self.path.startswith("/observer/"):
            self._observer_route()
        elif COMPONENT_PATH.match(self.path):
            self._proxy(browser_origin)
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    # --- observer API ------------------------------------------------------------------

    def _observer_route(self):
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        lab, store = self.server.lab, self.server.store
        if lab is None or store is None:
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        parts = path.strip("/").split("/")[1:]  # after "observer"
        get, post = self.command == "GET", self.command == "POST"
        if parts == ["api", "lab"] and get:
            self._json(200, self._cached_lab_summary(), revalidate=True)
        elif len(parts) == 3 and parts[:2] == ["api", "components"] and get:
            component = lab.component(parts[2])
            if component is None:
                self._json(404, {"error": "unknown_component"})
                return
            latest = {kind: store.latest(parts[2], kind)
                      for kind in ("container", "resources", "web", "splunk_health", "splunk_messages", "capture")}
            self._json(200, {"component": component, "latest": latest, "changes": store.changes(parts[2], limit=100)})
        elif len(parts) == 4 and parts[:2] == ["api", "components"] and parts[3] == "label" and post:
            body = self._read_json()
            if body is None:
                return
            try:
                lab.set_label(parts[2], body.get("name"), body.get("description"))
            except KeyError:
                self._json(404, {"error": "unknown_component"})
                return
            self._json(200, {"component": lab.component(parts[2])})
        elif len(parts) == 4 and parts[:2] == ["api", "components"] and parts[3] == "console" and get:
            component = lab.component(parts[2])
            if component is None:
                self._json(404, {"error": "unknown_component"})
                return
            checked_at = utc_now()
            try:
                text = lab.source.logs(parts[2], tail=60)
            except (OSError, ValueError) as error:
                text = f"(logs unavailable: {error.__class__.__name__})"
            self._json(200, {"component": parts[2], "source": f"podman logs --tail 60 {parts[2]}", "checked_at": checked_at,
                             "log": text, "resources": store.latest(parts[2], "resources"),
                             "container": store.latest(parts[2], "container")})
        elif len(parts) == 4 and parts[:2] == ["api", "components"] and parts[3] == "signin" and post:
            # Sign the owner's view in as the account the AI tests with, so the owner watches the same session.
            operator = self.server.assistant.operator if self.server.assistant else None
            if parts[2] not in lab.web_components():
                self._json(404, {"error": "unknown_component"})
                return
            if operator is None:
                self._json(409, {"error": "No test account: run the lab's ./observer.sh operator first"})
                return
            try:
                cookies = operator.web_session(parts[2])
            except (OSError, RuntimeError, ValueError) as error:
                self._json(502, {"error": str(error)[:200]})
                return
            body = json.dumps({"account": operator.username, "component": parts[2], "signed_in_at": utc_now()}).encode()
            self.send_response(200)
            for header in cookies:
                self.send_header("Set-Cookie", COOKIE_ROOT_PATH.sub(lambda match: f"{match.group(1)}/lab/{parts[2]}/", header))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif len(parts) == 4 and parts[:2] == ["api", "components"] and parts[3] == "screens" and get:
            component = lab.component(parts[2])
            if component is None:
                self._json(404, {"error": "unknown_component"})
                return
            apps = component["facts"].get("installed_apps") or {}
            self._json(200, {"component": parts[2], "web_path": component["web_path"], "screens": component["screens"],
                             "source": apps.get("source"), "checked_at": apps.get("checked_at")})
        elif parts == ["api", "at"] and get:
            try:
                moment = datetime.fromisoformat(query.get("time", [""])[0].replace("Z", "+00:00"))
                if moment.tzinfo is None:
                    raise ValueError
            except ValueError:
                self._json(400, {"error": "time must be an ISO 8601 timestamp with a zone"})
                return
            self._json(200, self._lab_at(moment.timestamp()))
        elif len(parts) == 3 and parts[:2] == ["api", "observations"] and parts[2].isdigit() and get:
            observation = store.observation(int(parts[2]))
            self._json(200 if observation else 404, observation or {"error": "unknown_observation"})
        elif parts == ["api", "changes"] and get:
            self._json(200, {"changes": store.changes(query.get("component", [None])[0], limit=300)})
        elif parts == ["api", "layout"] and get:
            self._json(200, {"layout": store.get_setting("layout")})
        elif parts == ["api", "layout"] and post:
            body = self._read_json()
            if body is None:
                return
            layout = body.get("layout")
            if not isinstance(layout, dict) or len(json.dumps(layout)) > 20000:
                self._json(400, {"error": "invalid_layout"})
                return
            layout["saved_at"] = utc_now()
            store.put_setting("layout", layout)
            self._json(200, {"layout": layout})
        elif parts == ["api", "discover"] and post:
            threading.Thread(target=self._background, args=(self.server.monitor.discover,), daemon=True).start()
            self._json(202, {"started": True})
        elif parts == ["api", "captures"] and post and self.server.capture:
            body = self._read_json() or {}
            components = [item for item in body.get("components", []) if item in lab.web_components()] or None
            threading.Thread(target=self.server.capture.run, args=(components,), daemon=True).start()
            self._json(202, {"started": True})
        elif parts == ["api", "coverage"] and get and self.server.coverage:
            self._json(200, self.server.coverage.full_map())
        elif parts == ["api", "coverage", "marks"] and post and self.server.coverage:
            body = self._read_json()
            if body is None:
                return
            coverage = self.server.coverage
            source = coverage.source_for(body.get("app"))
            if source is None:
                self._json(404, {"error": "unknown_app"})
                return
            try:
                status = coverage.record(source["app"], str(body.get("item") or ""), body.get("case"), body.get("status"),
                                         verdict=body.get("verdict"), run_id=body.get("run_id"),
                                         evidence=body.get("evidence"), note=body.get("note"), by="owner")
            except ValueError as error:
                self._json(400, {"error": str(error)})
                return
            self._json(200, {"status": status})
        elif parts == ["api", "checks"] and get and self.server.checks:
            self._json(200, self.server.checks.summary())
        elif parts == ["api", "checks", "run"] and post and self.server.checks:
            body = self._read_json()
            if body is None:
                return
            ids = [str(item) for item in body.get("ids") or []][:200] or None
            if self.server.checks.status["running"]:
                self._json(409, {"error": "A round of checks is already running"})
                return
            threading.Thread(target=self._background, args=(lambda: self.server.checks.run_round(ids, reason="asked for by the owner"),),
                             daemon=True).start()
            self._json(202, {"started": True})
        elif parts == ["api", "checks", "accept"] and post and self.server.checks:
            body = self._read_json()
            if body is None:
                return
            if body.get("remove"):
                done = self.server.checks.unaccept(str(body.get("id")))
            else:
                done = self.server.checks.accept(str(body.get("id")), body.get("reason"))
            self._json(200 if done else 409, {"done": done} if done else {"error": "Only a check that is failing now can be accepted, with a reason"})
        elif parts[:2] == ["api", "assistant"] and self.server.assistant:
            self._assistant_route(parts[2:], query, get, post)
        elif len(parts) == 3 and parts[:2] == ["api", "packages"] and get:
            # App packages the AI may upload through Splunk Web in the owner's view: only .tgz/.spl files
            # placed in the data directory's packages/ folder on this workstation.
            folder = (store.data_dir / "packages").resolve()
            target = (folder / parts[2]).resolve()
            if target.parent != folder or target.suffix not in {".tgz", ".spl"} or not target.is_file():
                self._send(404, b"Not found", "text/plain; charset=utf-8")
            else:
                self._send(200, target.read_bytes(), "application/gzip")
        elif len(parts) == 3 and parts[0] == "captures" and get and self.server.capture:
            capture_path = self.server.capture.path_for(f"{parts[1]}/{parts[2]}")
            if capture_path is None:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
            else:
                self._send(200, capture_path.read_bytes(), "image/jpeg", cache="private, max-age=86400")
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    def _assistant_route(self, parts, query, get, post):
        assistant = self.server.assistant
        if parts == [] and get:
            self._json(200, {"status": assistant.status(), "runs": self.server.store.runs()})
        elif parts == ["live"] and get:
            self._json(200, {"latest": self.server.store.latest_run()})
        elif parts == ["key"] and post:
            body = self._read_json()
            if body is None:
                return
            try:
                assistant.key.save(body.get("api_key"))
            except ValueError as error:
                self._json(400, {"error": str(error)})
                return
            self._json(200, {"status": assistant.status()})
        elif parts == ["runs"] and post:
            body = self._read_json()
            if body is None:
                return
            try:
                run = assistant.start(str(body.get("prompt") or ""))
            except (RuntimeError, ValueError) as error:
                self._json(400, {"error": str(error)})
                return
            self._json(202, run.view())
        elif len(parts) == 2 and parts[0] == "runs" and get:
            run = assistant.get(parts[1])
            since = query.get("since", ["0"])[0]
            if run is None:
                self._json(404, {"error": "unknown_run"})
            else:
                if run.record.get("status") in {"running", "waiting_for_approval"}:
                    self.server.store.page_watched(parts[1])  # a page is watching, so the shared view can be used
                self._json(200, run.view(int(since) if since.isdigit() else 0))
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "messages" and post:
            body = self._read_json()
            if body is None:
                return
            try:
                run = assistant.start(str(body.get("prompt") or ""), run_id=parts[1])
            except KeyError:
                self._json(404, {"error": "unknown_run"})
                return
            except (RuntimeError, ValueError) as error:
                self._json(400, {"error": str(error)})
                return
            self._json(202, run.view())
        elif len(parts) == 4 and parts[0] == "runs" and parts[2] == "page" and post:
            body = self._read_json()
            if body is None:
                return
            if not self.server.store.answer_page_request(parts[1], parts[3], body.get("ok"), body.get("result")):
                self._json(409, {"error": "no_pending_request"})
                return
            self._json(200, {"accepted": True})
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "control" and post:
            body = self._read_json()
            if body is None:
                return
            run = assistant.runs.get(parts[1])
            action = body.get("action")
            if run is None and action in {"pause", "takeover", "resume"} and self.server.store.run(parts[1]):
                self.server.store.page_watched(parts[1], paused=action != "resume")  # a terminal session waits
                self._json(200, {"paused": action != "resume"})
                return
            if run is None or not run.control(action):
                self._json(409, {"error": "invalid_control"})
                return
            self._json(200, {"paused": run.record.get("paused", False)})
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "pin" and post:
            body = self._read_json()
            if body is None:
                return
            run = assistant.pin(parts[1], body.get("pinned"))
            self._json(200 if run else 404, {"pinned": run.record.get("pinned") if run else None})
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "record" and get:
            run = assistant.get(parts[1])
            if run is None:
                self._json(404, {"error": "unknown_run"})
                return
            body = json.dumps(run.view(), indent=1).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", f'attachment; filename="observer-run-{parts[1]}.json"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif len(parts) >= 4 and parts[0] == "runs" and parts[2] == "evidence" and get:
            path = assistant.evidence_path(parts[1], "/".join(parts[3:]))
            if path is None:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
            else:
                self._send(200, path.read_bytes(), "image/jpeg", cache="private, max-age=86400")
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "stop" and post:
            self._json(200 if assistant.stop(parts[1]) else 404, {"stopping": True})
        elif len(parts) == 4 and parts[0] == "runs" and parts[2] == "approvals" and post:
            body = self._read_json()
            if body is None:
                return
            decision = {"approve": "approved", "deny": "declined"}.get(body.get("decision"))
            note = str(body.get("note") or "")[:500] or None
            if decision is None or not self.server.store.decide_approval(parts[1], parts[3], decision, note):
                self._json(409, {"error": "no_pending_approval"})
                return
            self._json(200, {"decided": True})
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    def _background(self, task):
        try:
            task()
        except Exception as error:
            if self.server.monitor:
                self.server.monitor.status["last_error"] = f"{utc_now()} {error.__class__.__name__}: {error}"

    def _cached_lab_summary(self):
        """The summary changes only when something is recorded, so open pages share one copy."""
        server = self.server
        key = (server.store.version, json.dumps([server.monitor.status if server.monitor else None,
                                                 server.capture.status if server.capture else None], default=str))
        if server.summary_cache[0] != key:
            server.summary_cache = (key, self._lab_summary())
        return server.summary_cache[1]

    def _lab_summary(self):
        lab, store = self.server.lab, self.server.store
        snapshot = lab.snapshot()
        for component in snapshot["components"]:
            # Screen lists are large; the wall fetches one component's list when it is focused.
            component["screen_count"] = len(component.pop("screens", []))
            status = {}
            for kind in ("container", "web", "splunk_health", "splunk_messages", "capture", "resources"):
                observation = store.latest(component["id"], kind)
                if observation:
                    status[kind] = {"id": observation["id"], "observed_at": observation["observed_at"],
                                    "source": observation["source"], "value": observation["value"]}
            last_capture = store.latest(component["id"], "capture")
            if last_capture and not last_capture["value"].get("file"):
                good = self._last_good_capture(component["id"])
                if good:
                    status["preview"] = good
            elif last_capture:
                status["preview"] = status["capture"]
            component["status"] = status
        snapshot["monitor"] = self.server.monitor.status if self.server.monitor else None
        snapshot["capture"] = self.server.capture.status if self.server.capture else None
        snapshot["recent_changes"] = store.changes(limit=40)
        snapshot["login_required"] = self.server.login is not None
        operator = self.server.assistant.operator if self.server.assistant else None
        snapshot["test_account"] = operator.username if operator else None
        snapshot["history_from"] = store.earliest()
        return snapshot

    def _lab_at(self, epoch):
        """Every component's recorded state at one moment, with each preview's distance from it."""
        lab, store = self.server.lab, self.server.store
        components = {}
        for component in lab.snapshot()["components"]:
            status = {}
            for kind in ("container", "web", "splunk_health", "splunk_messages", "resources"):
                observation = store.latest_before(component["id"], kind, epoch)
                if observation:
                    status[kind] = {"id": observation["id"], "observed_at": observation["observed_at"],
                                    "source": observation["source"], "value": observation["value"]}
            capture_state = {"missing": bool(component["web_path"]), "gap_seconds": None, "file_available": False}
            preview = store.latest_capture_before(component["id"], epoch) if component["web_path"] else None
            if preview:
                gap = epoch - datetime.fromisoformat(preview["observed_at"].replace("Z", "+00:00")).timestamp()
                available = self.server.capture is not None and self.server.capture.path_for(preview["value"]["file"]) is not None
                status["preview"] = {"id": preview["id"], "observed_at": preview["observed_at"], "source": preview["source"],
                                     "value": preview["value"]}
                capture_state = {"missing": gap > MISSING_CAPTURE_SECONDS or not available, "gap_seconds": round(gap),
                                 "file_available": available}
            status["capture_at_time"] = capture_state
            components[component["id"]] = status
        moment = datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return {"time": moment, "components": components,
                "changes": store.changes_between(epoch - 1800, epoch + 1800),
                "missing_capture_after_seconds": MISSING_CAPTURE_SECONDS}

    def _last_good_capture(self, component):
        rows = [change for change in self.server.store.changes(component, limit=200)
                if change["signal"] == "capture" and change["current"] == "captured"]
        for change in rows:
            observation = self.server.store.observation(change["observation_id"])
            if observation and observation["value"].get("file"):
                return {"id": observation["id"], "observed_at": observation["observed_at"],
                        "source": observation["source"], "value": observation["value"]}
        return None

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > 65536 or not self.headers.get("Content-Type", "").startswith("application/json"):
            self._json(400, {"error": "invalid_request"})
            return None
        try:
            self.body_read = True
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": "invalid_json"})
            return None
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return None
        return body

    def _json(self, status, value, revalidate=False):
        self._send(status, json.dumps(value).encode(), "application/json", cache="no-cache" if revalidate else "no-store",
                   revalidate=revalidate)

    def _browser_origin(self):
        try:
            host = self.headers.get("Host", "")
            parsed = urlsplit(f"{self.server.scheme}://{host}")
            if parsed.hostname in self.server.allowed_hosts and parsed.port == self.server.server_port:
                return f"{self.server.scheme}://{host}"
        except ValueError:
            pass
        return None

    def _same_origin_request(self, browser_origin):
        if self.headers.get("Sec-Fetch-Site") not in {None, "none", "same-origin"}:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != browser_origin:
            return False
        if self.command in {"POST", "PUT", "PATCH", "DELETE"}:
            referer = self.headers.get("Referer", "")
            return origin == browser_origin or referer.startswith(browser_origin + "/")
        return True

    def _session_token(self):
        try:
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            value = cookies.get(COOKIE_NAME)
            return value.value if value else None
        except CookieError:
            return None

    def _authenticated(self):
        return self.server.login is None or self.server.login.session_valid(self._session_token())

    def _login(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > 4096 or not self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            self._send(400, b"Invalid login request", "text/plain; charset=utf-8")
            return
        self.body_read = True
        fields = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        password = fields.get("password", [""])[0]
        if not self.server.login.password_matches(password):
            self._send(401, LOGIN_PAGE.read_bytes().replace(b"<!-- error -->", b"<p class='error'>Password not accepted.</p>"), "text/html; charset=utf-8")
            return
        token = self.server.login.new_session()
        self._redirect("/observer/", [
            ("Set-Cookie", f"{COOKIE_NAME}={token}; Max-Age={SESSION_LIFETIME_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Strict")
        ])

    def _redirect(self, location, headers=()):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for key, value in headers:
            self.send_header(key, value)
        self._end_headers()

    def _send(self, status, body, content_type, cache="no-store", revalidate=False):
        """Send a complete response. Large text is compressed for browsers that accept it; with
        revalidate the response carries a tag, and a request that already has that body gets 304."""
        headers = [("Content-Type", content_type), ("Cache-Control", cache), ("X-Frame-Options", "DENY")]
        if revalidate and status == 200:
            tag = '"' + hashlib.sha256(body).hexdigest()[:24] + '"'
            headers.append(("ETag", tag))
            if tag in [item.strip() for item in self.headers.get("If-None-Match", "").split(",")]:
                status, body = 304, b""
        if len(body) > 1024 and content_type.startswith(COMPRESSIBLE):
            headers.append(("Vary", "Accept-Encoding"))
            if "gzip" in self.headers.get("Accept-Encoding", ""):
                body = gzip.compress(body, compresslevel=5)
                headers.append(("Content-Encoding", "gzip"))
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        if status != 304:
            self.send_header("Content-Length", str(len(body)))
        self._end_headers()
        if self.command != "HEAD" and status != 304:
            self.wfile.write(body)

    def _upstream_response(self, body, headers):
        """Ask the router, on this connection's own upstream connection when it has one. A kept
        connection the router has since closed fails before any reply; that request is sent again."""
        for attempt in (0, 1):
            reused = self.upstream is not None
            if not reused:
                self.upstream = http.client.HTTPConnection(self.server.upstream_host, self.server.upstream_port,
                                                           timeout=UPSTREAM_TIMEOUT_SECONDS)
            try:
                self.upstream.request(self.command, self.path, body=body, headers=headers)
                return self.upstream.getresponse()
            except STALE_UPSTREAM:
                self._drop_upstream()
                if not reused or attempt:
                    raise
            except (OSError, http.client.HTTPException):
                self._drop_upstream()
                raise

    def _drop_upstream(self):
        if self.upstream is not None:
            self.upstream.close()
            self.upstream = None

    def _proxy(self, browser_origin):
        component = COMPONENT_PATH.match(self.path).group(1)
        if self.server.lab is not None and component not in self.server.lab.web_components():
            self._send(404, b"Unknown component", "text/plain; charset=utf-8")
            return
        if "Transfer-Encoding" in self.headers:
            self._send(411, b"Send the request with a Content-Length", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, b"Invalid request length", "text/plain; charset=utf-8")
            return
        if length < 0 or length > 8 * 1024 * 1024:
            self._send(413, b"Request too large", "text/plain; charset=utf-8")
            return
        self.body_read = True
        body = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_HEADERS | {"host", "content-length"}}
        if self.server.login and "Cookie" in headers:
            forwarded = [item.strip() for item in headers["Cookie"].split(";") if not item.strip().startswith(COOKIE_NAME + "=")]
            if forwarded:
                headers["Cookie"] = "; ".join(forwarded)
            else:
                headers.pop("Cookie")
        for key in ("Origin", "Referer"):
            if key in headers:
                headers[key] = headers[key].replace(browser_origin, self.server.upstream_origin, 1)

        response_started = False
        try:
            response = self._upstream_response(body, headers)
            # Without a length the body is sent in chunks as it arrives, which HTTP/1.0 clients cannot read.
            bodiless = self.command == "HEAD" or response.status in {204, 304} or response.status < 200
            sized = response.getheader("Content-Length") is not None
            chunked = not bodiless and not sized and self.request_version != "HTTP/1.0"
            self.send_response(response.status, response.reason)
            response_started = True
            for key, value in response.getheaders():
                if key.lower() in HOP_HEADERS:
                    continue
                if key.lower() == "location":
                    value = value.replace(self.server.upstream_origin, browser_origin, 1)
                elif key.lower() == "set-cookie":
                    # Every Splunk Web names its cookies after its own port (8000), so cookies set
                    # for "/" would collide across components. Keep each to its component's path.
                    value = COOKIE_ROOT_PATH.sub(lambda match: f"{match.group(1)}/lab/{component}/", value)
                self.send_header(key, value)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            elif not bodiless and not sized:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            if bodiless:
                response.read()
            elif chunked:
                while True:
                    block = response.read1(64 * 1024)
                    if not block:
                        break
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(block), block))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            else:
                shutil.copyfileobj(response, self.wfile, length=64 * 1024)
            if response.will_close:
                self._drop_upstream()
        except (OSError, http.client.HTTPException):
            self._drop_upstream()
            if response_started:
                self.close_connection = True  # the reply was cut short; the browser must not wait for more
            else:
                self._send(502, b"Component unavailable", "text/plain; charset=utf-8")

    def log_message(self, _format, *_args):
        # Browser requests can contain credentials or sensitive query parameters.
        pass


def create_server(address=("127.0.0.1", 8765), router_url="http://127.0.0.1:8190", *, auth_file=None, certfile=None, keyfile=None,
                  lab=None, store=None, capture=None, monitor=None, assistant=None, coverage=None, checks=None):
    return ObserverServer(address, router_url, auth_file=auth_file, certfile=certfile, keyfile=keyfile,
                          lab=lab, store=store, capture=capture, monitor=monitor, assistant=assistant, coverage=coverage, checks=checks)


def main():
    from observer.assistant import Assistant
    from observer.capture import Capture
    from observer.checks import Checks
    from observer.coverage import Coverage
    from observer.lab import DEFAULT_SPLUNK_CONFIG, Lab, OperatorAccount, PodmanSplunkSource
    from observer.monitor import Monitor
    from observer.store import DEFAULT_DATA_DIR, Store

    parser = argparse.ArgumentParser(description="Observe every Splunk lab component")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--lan-address", help="Private IPv4 address for HTTPS access from the LAN")
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--splunk-config", type=Path, default=DEFAULT_SPLUNK_CONFIG,
                        help="Read-only lab_observer account and router URL (written by the lab's observer.sh)")
    parser.add_argument("--no-capture", action="store_true", help="Do not take background screen previews")
    args = parser.parse_args()

    store = Store(args.data_dir)
    source = PodmanSplunkSource(args.splunk_config)
    lab = Lab(source, store)
    # Saved previews stay viewable with --no-capture; only new captures stop.
    capture = Capture(lab, store, args.data_dir)
    monitor = Monitor(lab, store, capture)
    operator_file = args.config_dir / "operator.json"
    operator = OperatorAccount(operator_file) if operator_file.exists() else None
    coverage = Coverage(store, lab, args.config_dir)
    assistant = Assistant(lab, store, args.config_dir, monitor, operator, capture, coverage)
    checks = Checks(lab, store, coverage, args.config_dir, assistant.lab_state, capture.read_pages)
    monitor.checks = checks
    options = dict(lab=lab, store=store, capture=capture, monitor=monitor, assistant=assistant, coverage=coverage, checks=checks)
    if args.lan_address:
        address = private_lan_address(args.lan_address)
        server = create_server(
            (address, args.port), source.router,
            auth_file=args.config_dir / "auth.json",
            certfile=args.config_dir / "cert.pem",
            keyfile=args.config_dir / "key.pem",
            **options,
        )
    else:
        address = "127.0.0.1"
        server = create_server((address, args.port), source.router, **options)
    monitor.start()
    if not args.no_capture:
        capture.start()
    print(f"Observer: {server.scheme}://{address}:{server.server_port}/observer/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        capture.stop()
        server.server_close()


if __name__ == "__main__":
    main()
