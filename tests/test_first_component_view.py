"""HTTP acceptance checks for direct views of every discovered Splunk Web component."""

import json
import tempfile
import unittest
from http.client import HTTPConnection

from observer.lab import Lab
from observer.server import create_server
from observer.store import Store
from tests.fakes import FakeSource, start, start_router


def call(port, method, path, body=None, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, response.getheaders(), response.read()
    connection.close()
    return result


def header(headers, name):
    return [value for key, value in headers if key.lower() == name.lower()]


class ComponentViewTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.router = start_router()
        self.store = Store(self.temp.name)
        self.lab = Lab(FakeSource(), self.store)
        self.lab.discover()
        self.observer = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{self.router.server_port}",
                                            lab=self.lab, store=self.store))
        self.port = self.observer.server_port

    def tearDown(self):
        self.observer.shutdown()
        self.observer.server_close()
        self.router.shutdown()
        self.router.server_close()
        self.store.db.close()
        self.temp.cleanup()

    def test_owner_can_open_every_discovered_web_component(self):
        status, _headers, page = call(self.port, "GET", "/observer/")
        self.assertEqual(status, 200)
        self.assertIn(b"Splunk Lab Observer", page)

        status, _headers, body = call(self.port, "GET", "/observer/api/lab")
        self.assertEqual(status, 200)
        lab = json.loads(body)
        web = sorted(item["id"] for item in lab["components"] if item["web_path"])
        self.assertEqual(web, ["p-cm", "p-idx1", "p-sh1", "p-sh2"])
        self.assertIsNone(next(item for item in lab["components"] if item["id"] == "p-uf")["web_path"])

        for name in web:
            status, headers, body = call(self.port, "GET", f"/lab/{name}/en-US/")
            self.assertEqual(status, 200)
            self.assertIn(f"Splunk Web of {name}".encode(), body)
            self.assertEqual(header(headers, "X-Frame-Options"), ["SAMEORIGIN"])

        status, headers, _body = call(self.port, "GET", "/lab/p-sh1/")
        self.assertEqual(status, 303)
        self.assertEqual(header(headers, "Location"), [f"http://127.0.0.1:{self.port}/lab/p-sh1/en-US/"])

    def test_each_component_keeps_its_own_session_cookies(self):
        _status, headers, _body = call(self.port, "GET", "/lab/p-sh1/en-US/")
        cookies = header(headers, "Set-Cookie")
        self.assertIn("session_id_8000=abc; HttpOnly; Path=/lab/p-sh1/", cookies)
        self.assertIn("cval=1; Path=/lab/p-sh1/en-US/account/", cookies)
        _status, headers, _body = call(self.port, "GET", "/lab/p-sh2/en-US/")
        self.assertIn("session_id_8000=abc; HttpOnly; Path=/lab/p-sh2/", header(headers, "Set-Cookie"))

    def test_unknown_and_unrouted_paths_are_refused(self):
        self.assertEqual(call(self.port, "GET", "/lab/p-uf/en-US/")[0], 404)
        self.assertEqual(call(self.port, "GET", "/lab/not-in-the-lab/en-US/")[0], 404)
        self.assertEqual(call(self.port, "GET", "/en-US/")[0], 404)
        self.assertEqual(call(self.port, "GET", "/lab/../observer/")[0], 404)

    def test_unavailable_component_is_explicit(self):
        self.router.shutdown()
        self.router.server_close()
        status, _headers, body = call(self.port, "GET", "/lab/p-sh1/en-US/")
        self.assertEqual(status, 502)
        self.assertIn(b"Component unavailable", body)

    def test_another_website_cannot_post_through_the_local_view(self):
        status, _headers, _body = call(self.port, "POST", "/lab/p-sh1/en-US/account/login", b"test=1",
                                       {"Origin": "http://another-website.test"})
        self.assertEqual(status, 403)
        status, _headers, _body = call(self.port, "POST", "/lab/p-sh1/en-US/account/login", b"test=1",
                                       {"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 200)
        status, _headers, _body = call(self.port, "GET", "/lab/p-sh1/en-US/", headers={"Host": "another-website.test"})
        self.assertEqual(status, 403)
        status, _headers, _body = call(self.port, "POST", "/observer/api/layout", json.dumps({"layout": {"tiles": []}}),
                                       {"Content-Type": "application/json", "Origin": "http://another-website.test"})
        self.assertEqual(status, 403)

    def test_proxy_cannot_bind_beyond_loopback(self):
        with self.assertRaises(ValueError):
            create_server(("0.0.0.0", 0), f"http://127.0.0.1:{self.router.server_port}")
        with self.assertRaises(ValueError):
            create_server(("127.0.0.1", 0), "http://192.168.3.86:8190")


if __name__ == "__main__":
    unittest.main()
