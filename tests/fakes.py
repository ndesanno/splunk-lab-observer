"""A small fake lab: podman containers, splunkd answers, and a Splunk Web router."""

import io
import json
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def server_info(name, roles, version="10.2.4"):
    return {"entry": [{"content": {"serverName": name, "version": version, "server_roles": roles}}]}


class FakeSource:
    username = "lab_observer"
    router = "http://127.0.0.1:1"

    def __init__(self):
        self.container_list = [
            {"name": "p-cm", "image": "docker.io/splunk/splunk:10.2.4", "state": "running", "status": "Up (healthy)", "health": "healthy", "started_at": 1, "ports": []},
            {"name": "p-idx1", "image": "docker.io/splunk/splunk:10.2.4", "state": "running", "status": "Up (healthy)", "health": "healthy", "started_at": 1, "ports": []},
            {"name": "p-sh1", "image": "docker.io/splunk/splunk:10.2.4", "state": "running", "status": "Up (healthy)", "health": "healthy", "started_at": 1, "ports": ["0.0.0.0:8101->8000"]},
            {"name": "p-sh2", "image": "docker.io/splunk/splunk:10.2.4", "state": "running", "status": "Up (healthy)", "health": "healthy", "started_at": 1, "ports": []},
            {"name": "p-lb", "image": "docker.io/library/haproxy:2.8.31-alpine", "state": "running", "status": "Up", "health": None, "started_at": 1, "ports": []},
            {"name": "p-uf", "image": "docker.io/splunk/universalforwarder:10.2.4", "state": "running", "status": "Up (healthy)", "health": "healthy", "started_at": 1, "ports": []},
        ]
        self.health = {"p-cm": "green", "p-idx1": "green", "p-sh1": "green", "p-sh2": "green"}
        self.web = {}

    def containers(self):
        return [dict(item) for item in self.container_list]

    def splunk_get(self, component, path, **_params):
        source = f"splunkd {component}{path}"
        state = next(item["state"] for item in self.container_list if item["name"] == component)
        if state != "running":
            raise urllib.error.URLError("connection refused")
        answers = {
            ("p-cm", "/services/server/info"): server_info("p-cm", ["cluster_manager", "license_manager"]),
            ("p-cm", "/services/cluster/config"): {"entry": [{"content": {"cluster_label": "hq"}}]},
            ("p-cm", "/services/cluster/manager/peers"): {"entry": [{"content": {"label": "p-idx1", "status": "Up"}}]},
            ("p-idx1", "/services/server/info"): server_info("p-idx1", ["indexer", "cluster_peer"]),
            ("p-sh1", "/services/server/info"): server_info("p-sh1", ["search_head", "shc_member", "shc_captain"]),
            ("p-sh2", "/services/server/info"): server_info("p-sh2", ["search_head", "shc_member"]),
            ("p-sh1", "/services/data/federated/provider"): {"entry": [{"name": "spoke", "content": {"hostPort": "p-lb:8089"}}]},
        }
        for member in ("p-sh1", "p-sh2"):
            answers[(member, "/services/shcluster/status")] = {"entry": [{"content": {
                "captain": {"label": "p-sh1"}, "peers": {"a": {"label": "p-sh1"}, "b": {"label": "p-sh2"}}}}]}
            answers[(member, "/services/shcluster/config")] = {"entry": [{"content": {"shcluster_label": "hq"}}]}
        if path == "/services/server/health/splunkd/details":
            return {"entry": [{"content": {"health": self.health[component], "features": {
                "Indexing": {"health": self.health[component], "features": {"Queue": {"health": self.health[component]}}}}}}]}, source
        if path == "/services/messages":
            return {"entry": []}, source
        if (component, path) not in answers:
            raise urllib.error.HTTPError(path, 403, "Forbidden", {}, io.BytesIO())
        return answers[(component, path)], source

    def web_status(self, component):
        return self.web.get(component, 200)

    def read_command(self, component, argv, user=None):
        if argv[:3] == ["/opt/splunk/bin/splunk", "cmd", "python3"]:
            return json.dumps([
                {"app": "TA-hindsight", "label": "Hindsight", "visible": True, "disabled": False, "version": "0.8.1", "build": "1",
                 "nav": '<nav><view name="hindsight_overview" default="true"/><collection label="Review"><view name="hindsight_apps"/>'
                        '<a href="/manager/search/data/indexes">Index settings</a></collection><a href="https://example.test">Docs</a></nav>',
                 "views": {"hindsight_overview": "Vulnerability Overview", "hindsight_apps": "Apps and Add-ons"}},
                {"app": "hidden_ta", "label": "Hidden", "visible": False, "disabled": False, "version": "1.0", "build": None, "nav": None, "views": {}},
                {"app": "federation_pulse_hq", "label": "Federation Pulse", "visible": True, "disabled": False, "version": "0.10.6",
                 "build": "100642", "nav": None, "views": {"pulse_hq_overview": "Federation Overview"}},
            ])
        if component == "p-lb":
            return "backend shc\n    server sh1 p-sh1:8089 check\n    server sh2 p-sh2:8089 check\n"
        if component == "p-uf":
            return "[tcpout:default]\nserver = p-idx1:9997\n"
        raise RuntimeError("unexpected command")

    def logs(self, component, tail=80):
        return f"{component} log line\n"

    def stats(self):
        return {item["name"]: {"cpu_percent": "1.0%", "mem_usage": "100MB / 1GB", "mem_percent": "10%"}
                for item in self.container_list if item["state"] == "running"}

    def password_for_capture(self):
        return "not-used"


class FakeRouterHandler(BaseHTTPRequestHandler):
    """Splunk Web behind the observer router: every component under /lab/<name>/."""

    def do_GET(self):
        parts = self.path.split("/")
        if len(parts) < 3 or parts[1] != "lab":
            self.send_error(404)
            return
        name = parts[2]
        if self.path == f"/lab/{name}/":
            self.send_response(303)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/lab/{name}/en-US/")
            self.end_headers()
            return
        self.server.last_cookie = self.headers.get("Cookie", "")
        body = f"<h1>Splunk Web of {name}</h1>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Set-Cookie", "session_id_8000=abc; HttpOnly; Path=/")
        self.send_header("Set-Cookie", f"cval=1; Path=/lab/{name}/en-US/account/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


def start_router():
    router = ThreadingHTTPServer(("127.0.0.1", 0), FakeRouterHandler)
    router.last_cookie = ""
    threading.Thread(target=router.serve_forever, daemon=True).start()
    return router


def start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
