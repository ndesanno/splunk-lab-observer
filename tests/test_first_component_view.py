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

    def test_a_browser_connection_is_reused_for_a_page_s_many_requests(self):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        seen = []
        for path in ("/lab/p-sh1/en-US/", "/lab/p-sh1/en-US/stream", "/lab/p-sh1/en-US/", "/observer/api/layout", "/lab/p-sh2/en-US/"):
            connection.request("GET", path)
            response = connection.getresponse()
            seen.append((response.status, response.version, response.getheader("Transfer-Encoding"), response.read()))
            self.assertFalse(response.will_close, path)
        connection.close()
        self.assertEqual([item[0] for item in seen], [200] * 5)
        self.assertEqual(seen[1][1:], (11, "chunked", b"first second third"))  # no length upstream: sent on in chunks
        self.assertIn(b"Splunk Web of p-sh2", seen[4][3])
        self.assertEqual(len(self.router.connections), 2)  # one kept upstream connection, replaced after the stream closed it

        # A request whose body is refused unread must not leave that body to be read as the next request.
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request("POST", "/observer/api/layout", "x" * 2000, {"Content-Type": "text/plain", "Origin": f"http://127.0.0.1:{self.port}"})
        response = connection.getresponse()
        self.assertEqual((response.status, response.will_close), (400, True))
        connection.close()

    def test_observer_data_is_compressed_and_not_resent_unchanged(self):
        status, headers, body = call(self.port, "GET", "/observer/api/lab", headers={"Accept-Encoding": "gzip"})
        self.assertEqual((status, header(headers, "Content-Encoding")), (200, ["gzip"]))
        import gzip
        lab = json.loads(gzip.decompress(body))
        self.assertEqual(len(lab["components"]), len(self.lab.snapshot()["components"]))
        tag = header(headers, "ETag")[0]
        status, headers, body = call(self.port, "GET", "/observer/api/lab", headers={"If-None-Match": tag})
        self.assertEqual((status, body), (304, b""))
        self.store.record("p-sh1", "web", "test", {"http_status": 503}, {"web": "unavailable"})
        status, _headers, body = call(self.port, "GET", "/observer/api/lab", headers={"If-None-Match": tag})
        self.assertEqual(status, 200)
        component = next(item for item in json.loads(body)["components"] if item["id"] == "p-sh1")
        self.assertEqual(component["status"]["web"]["value"], {"http_status": 503})
        status, headers, _body = call(self.port, "GET", "/observer/")
        self.assertEqual(call(self.port, "GET", "/observer/", headers={"If-None-Match": header(headers, "ETag")[0]})[0], 304)

    def test_proxy_cannot_bind_beyond_loopback(self):
        with self.assertRaises(ValueError):
            create_server(("0.0.0.0", 0), f"http://127.0.0.1:{self.router.server_port}")
        with self.assertRaises(ValueError):
            create_server(("127.0.0.1", 0), "http://192.168.1.50:8190")


if __name__ == "__main__":
    unittest.main()
