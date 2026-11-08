"""Public HTTPS and login behavior for access from another LAN device."""

import os
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from observer.server import create_server
from observer.setup_lan import provision_lan_credentials


class FakeSplunkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/en-US/")
            self.end_headers()
            return
        self.server.last_cookie = self.headers.get("Cookie", "")
        body = b"<h1>Splunk component</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def request(port, context, method, path, body=None, headers=None):
    connection = HTTPSConnection("127.0.0.1", port, context=context, timeout=4)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


class LanAccessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.credentials = provision_lan_credentials(Path(cls.temp.name), "127.0.0.1")
        cls.password = cls.credentials["password_file"].read_text().strip()
        cls.context = ssl.create_default_context(cafile=str(cls.credentials["certfile"]))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.splunk = ThreadingHTTPServer(("127.0.0.1", 0), FakeSplunkHandler)
        self.splunk.last_cookie = ""
        self.splunk_thread = threading.Thread(target=self.splunk.serve_forever, daemon=True)
        self.splunk_thread.start()
        self.observer = create_server(
            ("127.0.0.1", 0),
            f"http://127.0.0.1:{self.splunk.server_port}",
            auth_file=self.credentials["auth_file"],
            certfile=self.credentials["certfile"],
            keyfile=self.credentials["keyfile"],
        )
        self.observer_thread = threading.Thread(target=self.observer.serve_forever, daemon=True)
        self.observer_thread.start()

    def tearDown(self):
        self.observer.shutdown()
        self.observer.server_close()
        self.splunk.shutdown()
        self.splunk.server_close()

    def test_https_login_gates_every_component_request(self):
        port = self.observer.server_port
        status, headers, _body = request(port, self.context, "GET", "/observer/")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/observer/login")

        status, _headers, _body = request(port, self.context, "GET", "/en-US/")
        self.assertEqual(status, 303)
        self.assertEqual(self.splunk.last_cookie, "")

        status, _headers, _body = request(port, self.context, "GET", "/observer/api/component")
        self.assertEqual(status, 401)

        status, _headers, _body = request(port, self.context, "POST", "/observer/login", body="password=wrong", headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": f"https://127.0.0.1:{port}"})
        self.assertEqual(status, 401)

        status, headers, _body = request(port, self.context, "POST", "/observer/login", body=f"password={self.password}", headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": f"https://127.0.0.1:{port}"})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertIn("Secure", headers["Set-Cookie"])
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])

        status, _headers, body = request(port, self.context, "GET", "/observer/", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn(b"component-view", body)

        status, _headers, body = request(port, self.context, "GET", "/en-US/", headers={"Cookie": cookie + "; splunk_session=abc"})
        self.assertEqual(status, 200)
        self.assertIn(b"Splunk component", body)
        self.assertEqual(self.splunk.last_cookie, "splunk_session=abc")

        status, headers, _body = request(port, self.context, "GET", "/redirect", headers={"Cookie": cookie})
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], f"https://127.0.0.1:{port}/en-US/")

        status, _headers, _body = request(port, self.context, "POST", "/observer/logout", headers={"Cookie": cookie, "Origin": f"https://127.0.0.1:{port}"})
        self.assertEqual(status, 303)
        status, _headers, _body = request(port, self.context, "GET", "/observer/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)

    def test_cross_site_request_cannot_use_authenticated_proxy(self):
        port = self.observer.server_port
        status, headers, _body = request(port, self.context, "POST", "/observer/login", body=f"password={self.password}", headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": f"https://127.0.0.1:{port}"})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, _headers, _body = request(port, self.context, "GET", "/en-US/", headers={"Cookie": cookie, "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)

    def test_lan_listener_requires_https_and_login(self):
        with self.assertRaises(ValueError):
            create_server(("192.168.3.86", 0), f"http://127.0.0.1:{self.splunk.server_port}")
        self.assertEqual(os.stat(self.credentials["keyfile"]).st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.credentials["auth_file"]).st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.credentials["password_file"]).st_mode & 0o077, 0)

    def test_provisioning_refuses_a_git_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            with self.assertRaises(ValueError):
                provision_lan_credentials(checkout / "secrets", "127.0.0.1")
            self.assertFalse((checkout / "secrets").exists())
            with self.assertRaises(ValueError):
                provision_lan_credentials(checkout / ".git" / "secrets", "127.0.0.1")
            self.assertFalse((checkout / ".git" / "secrets").exists())


if __name__ == "__main__":
    unittest.main()
