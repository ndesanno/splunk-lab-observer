"""Discovery provenance, owner labels, health history, and saved wall layouts."""

import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path

from observer.capture import Capture
from observer.lab import Lab
from observer.monitor import Monitor
from observer.server import create_server
from observer.store import Store
from tests.fakes import FakeSource, start, start_router


def call(port, method, path, body=None):
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body)
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = response.status, json.loads(response.read() or b"null")
    connection.close()
    return result


class DiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.source = FakeSource()
        self.lab = Lab(self.source, self.store)
        self.registry = self.lab.discover()

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def test_every_discovered_fact_has_a_source_and_check_time(self):
        self.assertEqual(len(self.registry["components"]), 6)
        for component in self.registry["components"]:
            for name, item in component["facts"].items():
                self.assertTrue(item["source"], name)
                self.assertTrue(item["checked_at"].endswith("Z"), name)
        cm = self.lab.component("p-cm")
        self.assertEqual(cm["facts"]["server_roles"]["value"], ["cluster_manager", "license_manager"])
        self.assertEqual(cm["facts"]["server_roles"]["source"], "splunkd p-cm/services/server/info")

    def test_topology_reflects_clusters_balancers_forwarders_and_federation(self):
        groups = {group["id"]: group for group in self.registry["groups"]}
        self.assertEqual(groups["indexer-cluster:p-cm"]["members"], ["p-cm", "p-idx1"])
        self.assertEqual(groups["indexer-cluster:p-cm"]["label"], "hq")
        self.assertEqual(groups["search-head-cluster:hq"]["members"], ["p-sh1", "p-sh2"])
        self.assertEqual(groups["search-head-cluster:hq"]["captain"], "p-sh1")
        edges = {(item["from"], item["type"], item["to"]) for item in self.registry["relationships"]}
        self.assertIn(("p-cm", "manages indexer peer", "p-idx1"), edges)
        self.assertIn(("p-lb", "load balances", "p-sh1"), edges)
        self.assertIn(("p-uf", "sends data to", "p-idx1"), edges)
        self.assertIn(("p-sh1", "federated search provider", "p-lb"), edges)
        for item in self.registry["relationships"]:
            self.assertTrue(item["source"] and item["checked_at"])

    def test_owner_labels_stay_separate_from_discovered_facts(self):
        self.lab.set_label("p-sh1", "HQ search head 1", "Where Sample HQ runs")
        component = self.lab.component("p-sh1")
        self.assertEqual(component["owner_name"], "HQ search head 1")
        self.assertEqual(component["id"], "p-sh1")
        self.assertEqual(component["facts"]["server_name"]["value"], "p-sh1")
        self.assertTrue(component["owner_edited_at"])
        self.lab.discover()
        self.assertEqual(self.lab.component("p-sh1")["owner_name"], "HQ search head 1")
        self.lab.set_label("p-sh1", "", "")
        self.assertIsNone(self.lab.component("p-sh1")["owner_name"])
        with self.assertRaises(KeyError):
            self.lab.set_label("not-a-component", "x", "")

    def test_stopped_instance_is_discovered_without_splunk_facts(self):
        self.source.container_list[1]["state"] = "exited"
        registry = self.lab.discover()
        idx = next(item for item in registry["components"] if item["id"] == "p-idx1")
        self.assertEqual(idx["facts"]["container_state"]["value"], "exited")
        self.assertNotIn("splunk_version", idx["facts"])
        self.assertTrue(any(error["component"] == "p-idx1" for error in registry["errors"]))


class ScreenInventoryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.lab = Lab(FakeSource(), self.store)
        self.lab.discover()
        self.router = start_router()
        self.observer = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{self.router.server_port}", lab=self.lab, store=self.store))

    def tearDown(self):
        self.observer.shutdown()
        self.observer.server_close()
        self.router.shutdown()
        self.router.server_close()
        self.store.db.close()
        self.temp.cleanup()

    def test_screen_list_comes_from_installed_app_navigation(self):
        status, result = call(self.observer.server_port, "GET", "/observer/api/components/p-sh1/screens")
        self.assertEqual(status, 200)
        screens = [(item["app"], item["group"], item["label"], item["path"]) for item in result["screens"]]
        self.assertEqual(screens[:4], [
            ("TA-example", None, "Example Overview", "/en-US/app/TA-example/example_overview"),
            ("TA-example", "Review", "Apps and Add-ons", "/en-US/app/TA-example/example_apps"),
            ("TA-example", "Review", "Index settings", "/en-US/manager/search/data/indexes"),
            ("sample_hq", None, "Sample HQ", "/en-US/app/sample_hq/"),
        ])
        self.assertFalse(any(item["app"] == "hidden_ta" or "example.test" in item["path"] for item in result["screens"]))
        self.assertTrue(result["source"] and result["checked_at"])
        labels = {item["label"] for item in result["screens"] if item["app"] == "settings"}
        self.assertNotIn("Indexer clustering", labels)
        cm_labels = {item["label"] for item in self.lab.component("p-cm")["screens"] if item["app"] == "settings"}
        self.assertIn("Indexer clustering", cm_labels)
        versions = {app["app"]: app["version"] for app in self.lab.component("p-sh1")["facts"]["installed_apps"]["value"]}
        self.assertEqual(versions["sample_hq"], "0.10.6")

    def test_lab_summary_leaves_screen_lists_to_the_focused_view(self):
        _status, lab = call(self.observer.server_port, "GET", "/observer/api/lab")
        sh1 = next(item for item in lab["components"] if item["id"] == "p-sh1")
        self.assertNotIn("screens", sh1)
        self.assertEqual(sh1["screen_count"], len(self.lab.component("p-sh1")["screens"]))


class ReplayTest(unittest.TestCase):
    def test_time_selection_aligns_observations_and_marks_missing_captures(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            lab = Lab(FakeSource(), store)
            lab.discover()
            capture = Capture(lab, store, directory)
            (Path(directory) / "captures" / "p-sh1").mkdir()
            (Path(directory) / "captures" / "p-sh1" / "1.jpg").write_bytes(b"jpeg")
            store.record("p-sh1", "container", "podman ps", {"state": "running"}, {"container_state": "running"}, observed_at="2026-11-08T12:00:00Z")
            store.record("p-sh1", "capture", "headless", {"file": "p-sh1/1.jpg", "page": "/x"}, {"capture": "captured"}, observed_at="2026-11-08T12:00:00Z")
            store.record("p-sh1", "container", "podman ps", {"state": "exited"}, {"container_state": "exited"}, observed_at="2026-11-08T12:10:00Z")
            store.record("p-sh2", "container", "podman ps", {"state": "running"}, {"container_state": "running"}, observed_at="2026-11-08T12:00:00Z")
            router = start_router()
            observer = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{router.server_port}", lab=lab, store=store, capture=capture))
            try:
                status, at = call(observer.server_port, "GET", "/observer/api/at?time=2026-11-08T12:05:00Z")
                self.assertEqual(status, 200)
                sh1, sh2 = at["components"]["p-sh1"], at["components"]["p-sh2"]
                self.assertEqual(sh1["container"]["value"]["state"], "running")
                self.assertEqual(sh1["preview"]["value"]["file"], "p-sh1/1.jpg")
                self.assertEqual(sh1["capture_at_time"], {"missing": False, "gap_seconds": 300, "file_available": True})
                self.assertTrue(sh2["capture_at_time"]["missing"])
                self.assertNotIn("preview", sh2)
                self.assertFalse(at["components"]["p-uf"]["capture_at_time"]["missing"])
                self.assertIn(("p-sh1", "container_state", "exited"), {(c["component"], c["signal"], c["current"]) for c in at["changes"]})

                _status, later = call(observer.server_port, "GET", "/observer/api/at?time=2026-11-08T12:30:00Z")
                self.assertEqual(later["components"]["p-sh1"]["container"]["value"]["state"], "exited")
                self.assertTrue(later["components"]["p-sh1"]["capture_at_time"]["missing"])

                _status, before = call(observer.server_port, "GET", "/observer/api/at?time=2026-11-08T11:00:00Z")
                self.assertNotIn("container", before["components"]["p-sh1"])
                self.assertEqual(call(observer.server_port, "GET", "/observer/api/at?time=yesterday")[0], 400)
            finally:
                observer.shutdown()
                observer.server_close()
                router.shutdown()
                router.server_close()
                store.db.close()


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.source = FakeSource()
        self.lab = Lab(self.source, self.store)
        self.monitor = Monitor(self.lab, self.store)
        self.monitor.discover()
        self.router = start_router()
        self.observer = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{self.router.server_port}",
                                            lab=self.lab, store=self.store, monitor=self.monitor))

    def tearDown(self):
        self.observer.shutdown()
        self.observer.server_close()
        self.router.shutdown()
        self.router.server_close()
        self.store.db.close()
        self.temp.cleanup()

    def test_state_change_is_in_history_with_time_source_and_evidence(self):
        self.monitor.collect()
        self.source.container_list[1]["state"] = "exited"
        self.source.health["p-sh2"] = "yellow"
        self.source.web["p-sh1"] = 503
        self.monitor.collect()

        status, detail = call(self.observer.server_port, "GET", "/observer/api/components/p-idx1")
        self.assertEqual(status, 200)
        change = next(item for item in detail["changes"] if item["signal"] == "container_state" and item["previous"] == "running")
        self.assertEqual(change["current"], "exited")
        self.assertEqual(change["source"], "podman ps")
        self.assertTrue(change["observed_at"].endswith("Z"))
        status, observation = call(self.observer.server_port, "GET", f"/observer/api/observations/{change['observation_id']}")
        self.assertEqual(status, 200)
        self.assertEqual(observation["value"]["state"], "exited")

        changes = {(item["component"], item["signal"], item["previous"], item["current"]) for item in self.store.changes()}
        self.assertIn(("p-sh2", "splunk_health", "green", "yellow"), changes)
        self.assertIn(("p-sh1", "web", "available", "unavailable"), changes)
        health = self.store.latest("p-sh2", "splunk_health")
        self.assertEqual(health["value"]["degraded_features"], {"Indexing/Queue": "yellow"})

    def test_component_status_links_to_its_direct_observations(self):
        self.monitor.collect()
        status, lab = call(self.observer.server_port, "GET", "/observer/api/lab")
        self.assertEqual(status, 200)
        sh1 = next(item for item in lab["components"] if item["id"] == "p-sh1")
        for kind in ("container", "web", "splunk_health", "resources"):
            item = sh1["status"][kind]
            self.assertTrue(item["source"] and item["observed_at"])
            status, observation = call(self.observer.server_port, "GET", f"/observer/api/observations/{item['id']}")
            self.assertEqual((status, observation["kind"]), (200, kind))

    def test_unchanged_status_adds_no_history(self):
        self.monitor.collect()
        before = len(self.store.changes())
        self.monitor.collect()
        self.assertEqual(len(self.store.changes()), before)

    def test_old_observations_are_pruned_after_thirty_days(self):
        self.store.record("old", "web", "test", {"http_status": 200}, {"web": "available"}, observed_at="2026-01-01T00:00:00Z")
        self.store.record("new", "web", "test", {"http_status": 200}, {"web": "available"})
        self.store.prune(now=time.time())
        self.assertIsNone(self.store.latest("old", "web"))
        self.assertIsNotNone(self.store.latest("new", "web"))


class LayoutTest(unittest.TestCase):
    def test_an_unchanged_fact_is_stored_once_with_its_last_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            for minute in range(5):
                store.record("p-sh1", "web", "GET /login", {"http_status": 200}, {"web": "available"},
                             observed_at=f"2026-11-01T10:0{minute}:00Z")
            first = store.latest("p-sh1", "web")
            self.assertEqual((first["since"], first["observed_at"]), ("2026-11-01T10:00:00Z", "2026-11-01T10:04:00Z"))
            store.record("p-sh1", "web", "GET /login", {"http_status": 503}, {"web": "unavailable"}, observed_at="2026-11-01T10:05:00Z")
            store.record("p-sh1", "web", "GET /login", {"http_status": 503}, {"web": "unavailable"}, observed_at="2026-11-01T10:06:00Z")
            rows = store.db.execute("SELECT count(*) FROM observations WHERE component = 'p-sh1' AND kind = 'web'").fetchone()[0]
            self.assertEqual(rows, 2)
            change = [item for item in store.changes("p-sh1") if item["current"] == "unavailable"][0]
            self.assertEqual(store.observation(change["observation_id"])["value"], {"http_status": 503})
            # Looking back to 10:02, the first value held and had been confirmed by then.
            past = store.latest_before("p-sh1", "web", datetime(2026, 11, 1, 10, 2, 30, tzinfo=timezone.utc).timestamp())
            self.assertEqual((past["value"], past["observed_at"]), ({"http_status": 200}, "2026-11-01T10:02:30Z"))
            # A fact still being confirmed is not pruned however long ago it was first seen.
            store.prune(now=datetime(2026, 12, 1, 10, 5, 30, tzinfo=timezone.utc).timestamp())
            self.assertEqual(store.latest("p-sh1", "web")["value"], {"http_status": 503})
            store.db.close()

    def test_a_store_written_before_repeats_were_merged_is_tidied_once(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as directory:
            old = sqlite3.connect(Path(directory) / "observer.db")
            old.executescript("""
                CREATE TABLE observations (id INTEGER PRIMARY KEY, component TEXT NOT NULL, kind TEXT NOT NULL,
                    observed_at TEXT NOT NULL, epoch REAL NOT NULL, source TEXT NOT NULL, value TEXT NOT NULL);
                CREATE TABLE changes (id INTEGER PRIMARY KEY, component TEXT NOT NULL, signal TEXT NOT NULL,
                    observed_at TEXT NOT NULL, epoch REAL NOT NULL, previous TEXT, current TEXT, source TEXT NOT NULL, observation_id INTEGER);
            """)
            values = ['{"a": 1}', '{"a": 1}', '{"a": 1}', '{"a": 2}', '{"a": 2}', '{"a": 1}']
            for index, value in enumerate(values):
                old.execute("INSERT INTO observations (component, kind, observed_at, epoch, source, value) VALUES ('c', 'k', ?, ?, 's', ?)",
                            (f"2026-11-01T10:0{index}:00Z", 1000.0 + index, value))
            old.execute("INSERT INTO changes (component, signal, observed_at, epoch, previous, current, source, observation_id)"
                        " VALUES ('c', 'x', '2026-11-01T10:03:00Z', 1003, '1', '2', 's', 4)")
            old.commit(); old.close()
            store = Store(directory)
            rows = [tuple(row) for row in store.db.execute("SELECT id, value, observed_at, seen_at FROM observations ORDER BY id")]
            self.assertEqual(rows, [(1, '{"a": 1}', "2026-11-01T10:00:00Z", "2026-11-01T10:02:00Z"),
                                    (4, '{"a": 2}', "2026-11-01T10:03:00Z", "2026-11-01T10:04:00Z"),
                                    (6, '{"a": 1}', "2026-11-01T10:05:00Z", "2026-11-01T10:05:00Z")])
            store.db.close()

    def test_saved_selection_is_restored_after_reopening(self):
        with tempfile.TemporaryDirectory() as directory:
            router = start_router()
            for attempt in range(2):
                store = Store(directory)
                lab = Lab(FakeSource(), store)
                lab.discover()
                observer = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{router.server_port}", lab=lab, store=store))
                if attempt == 0:
                    status, saved = call(observer.server_port, "POST", "/observer/api/layout",
                                         {"layout": {"columns": 2, "tiles": [{"id": "p-sh2", "live": True}, {"id": "p-uf", "live": False}]}})
                    self.assertEqual(status, 200)
                    self.assertTrue(saved["layout"]["saved_at"])
                else:
                    status, restored = call(observer.server_port, "GET", "/observer/api/layout")
                    self.assertEqual(status, 200)
                    self.assertEqual(restored["layout"]["tiles"], [{"id": "p-sh2", "live": True}, {"id": "p-uf", "live": False}])
                    self.assertEqual(restored["layout"]["columns"], 2)
                observer.shutdown()
                observer.server_close()
                store.db.close()
            router.shutdown()
            router.server_close()

    def test_capture_files_cannot_escape_their_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            capture = Capture(Lab(FakeSource(), store), store, directory)
            (Path(directory) / "captures" / "p-sh1").mkdir()
            (Path(directory) / "captures" / "p-sh1" / "1.jpg").write_bytes(b"jpeg")
            self.assertIsNotNone(capture.path_for("p-sh1/1.jpg"))
            self.assertIsNone(capture.path_for("../observer.db"))
            self.assertIsNone(capture.path_for("p-sh1/../../observer.db"))
            (Path(directory) / "captures" / ".env-secret").write_text("OBSERVER_PASSWORD=x")
            self.assertIsNone(capture.path_for("./.env-secret"))
            store.db.close()


if __name__ == "__main__":
    unittest.main()
