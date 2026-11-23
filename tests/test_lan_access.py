"""Public HTTPS and login behavior for access from another LAN device."""

import os
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.client import HTTPSConnection
from pathlib import Path

from observer.lab import Lab
from observer.server import create_server
from observer.setup_lan import provision_lan_credentials
from observer.store import Store
from tests.fakes import FakeSource, start_router


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
        self.splunk = start_router()
        self.data = tempfile.TemporaryDirectory()
        self.store = Store(self.data.name)
        self.lab = Lab(FakeSource(), self.store)
        self.lab.discover()
        self.observer = create_server(
            ("127.0.0.1", 0),
            f"http://127.0.0.1:{self.splunk.server_port}",
            auth_file=self.credentials["auth_file"],
            certfile=self.credentials["certfile"],
            keyfile=self.credentials["keyfile"],
            lab=self.lab, store=self.store,
        )
        self.observer_thread = threading.Thread(target=self.observer.serve_forever, daemon=True)
        self.observer_thread.start()

    def tearDown(self):
        self.observer.shutdown()
        self.observer.server_close()
        self.splunk.shutdown()
        self.splunk.server_close()
        self.store.db.close()
        self.data.cleanup()

    def test_https_login_gates_every_component_request(self):
        port = self.observer.server_port
        status, headers, _body = request(port, self.context, "GET", "/observer/")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/observer/login")

        status, _headers, _body = request(port, self.context, "GET", "/lab/p-sh1/en-US/")
        self.assertEqual(status, 303)
        self.assertEqual(self.splunk.last_cookie, "")

        status, _headers, _body = request(port, self.context, "GET", "/observer/api/lab")
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
        self.assertIn(b"Splunk Lab Observer", body)

        status, _headers, body = request(port, self.context, "GET", "/lab/p-sh1/en-US/", headers={"Cookie": cookie + "; splunk_session=abc"})
        self.assertEqual(status, 200)
        self.assertIn(b"Splunk Web of p-sh1", body)
        self.assertEqual(self.splunk.last_cookie, "splunk_session=abc")

        status, headers, _body = request(port, self.context, "GET", "/lab/p-sh1/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], f"https://127.0.0.1:{port}/lab/p-sh1/en-US/")

        status, _headers, _body = request(port, self.context, "POST", "/observer/logout", headers={"Cookie": cookie, "Origin": f"https://127.0.0.1:{port}"})
        self.assertEqual(status, 303)
        status, _headers, _body = request(port, self.context, "GET", "/observer/", headers={"Cookie": cookie})
        self.assertEqual(status, 303)

    def test_a_stalled_tls_handshake_does_not_hold_up_other_connections(self):
        import socket
        stalled = [socket.create_connection(("127.0.0.1", self.observer.server_port)) for _ in range(3)]  # never speak TLS
        try:
            status, _headers, _body = request(self.observer.server_port, self.context, "GET", "/observer/login")
            self.assertEqual(status, 200)
        finally:
            for item in stalled:
                item.close()

    def test_cross_site_request_cannot_use_authenticated_proxy(self):
        port = self.observer.server_port
        status, headers, _body = request(port, self.context, "POST", "/observer/login", body=f"password={self.password}", headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": f"https://127.0.0.1:{port}"})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, _headers, _body = request(port, self.context, "GET", "/lab/p-sh1/en-US/", headers={"Cookie": cookie, "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)

    def test_lan_listener_requires_https_and_login(self):
        with self.assertRaises(ValueError):
            create_server(("192.168.1.50", 0), f"http://127.0.0.1:{self.splunk.server_port}")
        self.assertEqual(os.stat(self.credentials["keyfile"]).st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.credentials["auth_file"]).st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.credentials["password_file"]).st_mode & 0o077, 0)

    def test_service_unit_runs_this_checkout_with_the_chosen_address(self):
        from observer.service import unit_text
        text = unit_text(Path("/opt/venv/bin/python"), Path("/srv/observer"), ["--port", "8766", "--lan-address", "192.168.1.50"])
        self.assertIn("ExecStart=/opt/venv/bin/python -m observer.server --port 8766 --lan-address 192.168.1.50\n", text)
        self.assertIn("WorkingDirectory=/srv/observer\n", text)
        self.assertIn("Restart=on-failure", text)

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
