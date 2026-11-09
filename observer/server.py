"""Serve the observer page and a same-origin view of one Splunk component."""

import argparse
import http.client
import json
import re
import shutil
import ssl
import threading
import time
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
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


class ObserverServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, upstream_url, auth_file=None, certfile=None, keyfile=None, lab=None, store=None, capture=None, monitor=None, assistant=None):
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
        super().__init__(address, ObserverHandler)
        if context is not None:
            self.socket = context.wrap_socket(self.socket, server_side=True)


class ObserverHandler(BaseHTTPRequestHandler):
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

    def _route(self):
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
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
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
            self._json(200, self._lab_summary())
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
        elif parts[:2] == ["api", "assistant"] and self.server.assistant:
            self._assistant_route(parts[2:], query, get, post)
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
                live = assistant.runs.get(parts[1])
                if live is not None:  # a page is watching, so the shared view can be used
                    live.page_seen = time.time()
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
            run = assistant.runs.get(parts[1])
            if run is None or not run.page_result(parts[3], body.get("ok"), body.get("result")):
                self._json(409, {"error": "no_pending_request"})
                return
            self._json(200, {"accepted": True})
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "control" and post:
            body = self._read_json()
            if body is None:
                return
            run = assistant.runs.get(parts[1])
            if run is None or not run.control(body.get("action")):
                self._json(409, {"error": "invalid_control"})
                return
            self._json(200, {"paused": run.record.get("paused", False)})
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "stop" and post:
            self._json(200 if assistant.stop(parts[1]) else 404, {"stopping": True})
        elif len(parts) == 4 and parts[0] == "runs" and parts[2] == "approvals" and post:
            body = self._read_json()
            if body is None:
                return
            run = assistant.runs.get(parts[1])
            if run is None or not run.decide(parts[3], body.get("decision"), body.get("note")):
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
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": "invalid_json"})
            return None
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return None
        return body

    def _json(self, status, value):
        self._send(status, json.dumps(value).encode(), "application/json")

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
        self.end_headers()

    def _send(self, status, body, content_type, cache="no-store"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self, browser_origin):
        component = COMPONENT_PATH.match(self.path).group(1)
        if self.server.lab is not None and component not in self.server.lab.web_components():
            self._send(404, b"Unknown component", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, b"Invalid request length", "text/plain; charset=utf-8")
            return
        if length < 0 or length > 8 * 1024 * 1024:
            self._send(413, b"Request too large", "text/plain; charset=utf-8")
            return
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

        connection = http.client.HTTPConnection(self.server.upstream_host, self.server.upstream_port, timeout=15)
        response_started = False
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
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
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                shutil.copyfileobj(response, self.wfile, length=64 * 1024)
            self.close_connection = True
        except (OSError, http.client.HTTPException):
            if not response_started:
                self._send(502, b"Component unavailable", "text/plain; charset=utf-8")
        finally:
            connection.close()

    def log_message(self, _format, *_args):
        # Browser requests can contain credentials or sensitive query parameters.
        pass


def create_server(address=("127.0.0.1", 8765), router_url="http://127.0.0.1:8190", *, auth_file=None, certfile=None, keyfile=None,
                  lab=None, store=None, capture=None, monitor=None, assistant=None):
    return ObserverServer(address, router_url, auth_file=auth_file, certfile=certfile, keyfile=keyfile,
                          lab=lab, store=store, capture=capture, monitor=monitor, assistant=assistant)


def main():
    from observer.assistant import Assistant
    from observer.capture import Capture
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
    assistant = Assistant(lab, store, args.config_dir, monitor, operator)
    options = dict(lab=lab, store=store, capture=capture, monitor=monitor, assistant=assistant)
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
