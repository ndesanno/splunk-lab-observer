"""Serve the observer page and a same-origin view of one Splunk component."""

import argparse
import http.client
import json
import shutil
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


PAGE = Path(__file__).with_name("view.html")
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


class ObserverServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, upstream_url):
        if address[0] not in {"127.0.0.1", "localhost"}:
            raise ValueError("The observer must bind to loopback")
        parsed = urlsplit(upstream_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.path not in {"", "/"}:
            raise ValueError("The first component must be an HTTP service on this workstation")
        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port or 80
        self.upstream_origin = f"http://{self.upstream_host}:{self.upstream_port}"
        super().__init__(address, ObserverHandler)


class ObserverHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/observer/":
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/observer/api/component":
            self._send(200, json.dumps(self._observe_component()).encode(), "application/json")
        else:
            self._proxy()

    def do_HEAD(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_PATCH(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _observe_component(self):
        checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        discovery_state = "not_detected"
        try:
            connection = http.client.HTTPConnection(self.server.upstream_host, self.server.upstream_port, timeout=3)
            connection.request("GET", "/")
            response = connection.getresponse()
            status = response.status
            discovery_state = "detected" if "splunkd" in response.getheader("Server", "").lower() else "unverified"
            connection.close()
            availability = "available" if status < 500 else "unavailable"
        except (OSError, http.client.HTTPException):
            status = None
            availability = "unavailable"
        return {
            "id": f"splunk-web-{self.server.upstream_port}",
            "name": f"Splunk web :{self.server.upstream_port}" if discovery_state == "detected" else f"Component :{self.server.upstream_port}",
            "discovery_state": discovery_state,
            "availability": availability,
            "checked_at": checked_at,
            "source": f"{self.server.upstream_origin}/",
            "upstream_status": status,
        }

    def _proxy(self):
        try:
            browser_host = urlsplit(f"http://{self.headers.get('Host', '')}")
            valid_host = browser_host.hostname in {"127.0.0.1", "localhost"} and browser_host.port == self.server.server_port
        except ValueError:
            valid_host = False
        if not valid_host:
            self._send(403, b"Local access only", "text/plain; charset=utf-8")
            return
        browser_origin = f"http://{self.headers['Host']}"
        if self.command in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = self.headers.get("Origin")
            referer = self.headers.get("Referer", "")
            if origin != browser_origin and not (origin is None and referer.startswith(browser_origin + "/")):
                self._send(403, b"Request origin not allowed", "text/plain; charset=utf-8")
                return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, b"Invalid request length", "text/plain; charset=utf-8")
            return
        if length > 8 * 1024 * 1024:
            self._send(413, b"Request too large", "text/plain; charset=utf-8")
            return
        body = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_HEADERS | {"host", "content-length"}}
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


def create_server(address=("127.0.0.1", 8765), component_url="http://127.0.0.1:8100"):
    return ObserverServer(address, component_url)


def main():
    parser = argparse.ArgumentParser(description="Local view of one Splunk lab component")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--component-url", default="http://127.0.0.1:8100")
    args = parser.parse_args()
    server = create_server(("127.0.0.1", args.port), args.component_url)
    print(f"Observer: http://127.0.0.1:{server.server_port}/observer/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
