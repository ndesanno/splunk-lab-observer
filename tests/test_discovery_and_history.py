"""Discovery provenance, owner labels, health history, and saved wall layouts."""

import json
import tempfile
import time
import unittest
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
        self.lab.set_label("p-sh1", "HQ search head 1", "Where Pulse HQ runs")
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
