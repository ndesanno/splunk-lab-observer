"""HTTP acceptance checks for the first direct component view."""

import json
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from observer.server import create_server


class FakeSplunkHandler(BaseHTTPRequestHandler):
    server_version = "Splunkd"

    def do_GET(self):
        if self.path == "/":
            self.send_response(303)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/en-US/")
            self.end_headers()
            return
        if self.path == "/en-US/":
            body = b"<h1>Real lab component screen</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


def start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def get(port, path):
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request("GET", path)
    response = connection.getresponse()
    status, headers, body = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return status, headers, body


class FirstComponentViewTest(unittest.TestCase):
    def setUp(self):
        self.splunk = ThreadingHTTPServer(("127.0.0.1", 0), FakeSplunkHandler)
        start(self.splunk)
        self.observer = create_server(("127.0.0.1", 0), f"http://127.0.0.1:{self.splunk.server_port}")
        start(self.observer)

    def tearDown(self):
        self.observer.shutdown()
        self.observer.server_close()
        self.splunk.shutdown()
        self.splunk.server_close()

    def test_owner_can_open_a_direct_component_view(self):
        status, _headers, page = get(self.observer.server_port, "/observer/")
        self.assertEqual(status, 200)
        self.assertIn(b'<iframe id="component-view" src="/en-US/"', page)

        status, _headers, body = get(self.observer.server_port, "/observer/api/component")
        self.assertEqual(status, 200)
        observation = json.loads(body)
        self.assertEqual(observation["availability"], "available")
        self.assertEqual(observation["discovery_state"], "detected")
        self.assertEqual(observation["name"], f"Splunk web :{self.splunk.server_port}")
        self.assertEqual(observation["source"], f"http://127.0.0.1:{self.splunk.server_port}/")
        self.assertIn("checked_at", observation)

        status, headers, body = get(self.observer.server_port, "/en-US/")
        self.assertEqual(status, 200)
        self.assertIn(b"Real lab component screen", body)
        self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN")

        status, _headers, body = get(self.observer.server_port, "/observer/api/component")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["view_source"], f"http://127.0.0.1:{self.splunk.server_port}/en-US/")
        self.assertIsNotNone(json.loads(body)["view_response_at"])

        status, headers, _body = get(self.observer.server_port, "/")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], f"http://127.0.0.1:{self.observer.server_port}/en-US/")

    def test_unavailable_component_is_explicit(self):
        self.splunk.shutdown()
        self.splunk.server_close()

        status, _headers, body = get(self.observer.server_port, "/observer/api/component")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["availability"], "unavailable")

        status, _headers, body = get(self.observer.server_port, "/en-US/")
        self.assertEqual(status, 502)
        self.assertIn(b"Component unavailable", body)

    def test_another_website_cannot_post_through_the_local_view(self):
        connection = HTTPConnection("127.0.0.1", self.observer.server_port, timeout=3)
        connection.request("POST", "/en-US/account/login", body=b"test=1", headers={"Origin": "http://another-website.test"})
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        connection.close()

        connection = HTTPConnection("127.0.0.1", self.observer.server_port, timeout=3)
        connection.request("POST", "/en-US/account/login", body=b"test=1", headers={"Origin": f"http://127.0.0.1:{self.observer.server_port}"})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        response.read()
        connection.close()

        connection = HTTPConnection("127.0.0.1", self.observer.server_port, timeout=3)
        connection.request("GET", "/en-US/", headers={"Host": "another-website.test"})
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        connection.close()

    def test_proxy_cannot_bind_beyond_loopback(self):
        with self.assertRaises(ValueError):
            create_server(("0.0.0.0", 0), f"http://127.0.0.1:{self.splunk.server_port}")


if __name__ == "__main__":
    unittest.main()
