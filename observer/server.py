"""Serve the observer page and a same-origin view of one Splunk component."""

import argparse
import http.client
import json
import shutil
import ssl
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from observer.auth import COOKIE_NAME, SESSION_LIFETIME_SECONDS, OwnerLogin
from observer.setup_lan import DEFAULT_CONFIG_DIR, private_lan_address


PAGE = Path(__file__).with_name("view.html")
LOGIN_PAGE = Path(__file__).with_name("login.html")
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


class ObserverServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, upstream_url, auth_file=None, certfile=None, keyfile=None):
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
            raise ValueError("The first component must be an HTTP service on this workstation")
        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port or 80
        self.upstream_origin = f"http://{self.upstream_host}:{self.upstream_port}"
        self.scheme = "https" if secure_mode else "http"
        self.allowed_hosts = {address[0]} if secure_mode else {"127.0.0.1", "localhost"}
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
        elif self.path == "/observer/api/component" and self.command == "GET":
            observation = self._observe_component()
            observation["login_required"] = self.server.login is not None
            self._send(200, json.dumps(observation).encode(), "application/json")
        else:
            self._proxy(browser_origin)

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

    def _proxy(self, browser_origin):
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


def create_server(address=("127.0.0.1", 8765), component_url="http://127.0.0.1:8100", *, auth_file=None, certfile=None, keyfile=None):
    return ObserverServer(address, component_url, auth_file=auth_file, certfile=certfile, keyfile=keyfile)


def main():
    parser = argparse.ArgumentParser(description="Local view of one Splunk lab component")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--component-url", default="http://127.0.0.1:8100")
    parser.add_argument("--lan-address", help="Private IPv4 address for HTTPS access from the LAN")
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR)
    args = parser.parse_args()
    if args.lan_address:
        address = private_lan_address(args.lan_address)
        server = create_server(
            (address, args.port), args.component_url,
            auth_file=args.config_dir / "auth.json",
            certfile=args.config_dir / "cert.pem",
            keyfile=args.config_dir / "key.pem",
        )
    else:
        address = "127.0.0.1"
        server = create_server((address, args.port), args.component_url)
    print(f"Observer: {server.scheme}://{address}:{server.server_port}/observer/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
