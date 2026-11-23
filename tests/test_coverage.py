"""The coverage map: an app's features and screens from its source at the installed version, and tested cases."""

import json
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from observer import assistant as assistant_module
from observer.coverage import Coverage
from observer.lab import Lab
from observer.server import create_server
from observer.store import Store
from tests.fakes import FakeSource, start, start_router
from tests.test_assistant import AssistantFixture, message, tool_use
from tests.test_discovery_and_history import call

APP_CONF = "[launcher]\nversion = {version}\n\n[install]\nbuild = {build}\n\n[ui]\nlabel = Example\n"
OVERVIEW = """<form version="1.1">
  <label>Example Overview</label>
  <row>
    <panel>
      <title>Forwarders with findings</title>
    </panel>
    <panel><title>Findings by
      severity</title></panel>
  </row>
</form>
"""
SAVED = """[default]
dispatch.earliest_time = -24h

[Example - Update Findings]
cron_schedule = 20 */4 * * *
enableSched = 1

[Example - Critical Forwarders]
cron_schedule = 30 7 * * *
enableSched = 1
action.email = 1
disabled = 1

[Example - Lookup Report]
search = | inputlookup example_findings
"""
APP_TSX = """export function App() {
  return (<>
    <Heading level={2}>Agency directory</Heading>
    <Button label="Save agency" appearance="primary" />
    {mode === "edit" ? <Heading level={3}>Edit agency</Heading> : <Heading level={3}>Agency directory</Heading>}
    <Heading level={3}>{dynamicTitle}</Heading>
  </>);
}
"""


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.test", *args],
                   check=True, capture_output=True)


def write(root, path, text):
    target = Path(root) / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


class CoverageFixture(unittest.TestCase):
    """A git repo with TA-example tagged v0.8.1 (installed in the fake lab) and a newer default branch."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.repo = root / "example"
        git(root, "init", "-q", "-b", "main", str(self.repo))
        app = "TA-example/default"
        write(self.repo, f"{app}/app.conf", APP_CONF.format(version="0.8.1", build="1"))
        write(self.repo, f"{app}/data/ui/nav/default.xml", '<nav><view name="example_overview" default="true"/></nav>')
        write(self.repo, f"{app}/data/ui/views/example_overview.xml", OVERVIEW)
        write(self.repo, f"{app}/data/ui/views/example_settings.xml", "<dashboard><label>Settings</label></dashboard>")
        write(self.repo, f"{app}/savedsearches.conf", SAVED)
        write(self.repo, f"{app}/commands.conf", "[examplecheck]\nfilename = examplecheck.py\n")
        write(self.repo, f"{app}/restmap.conf", "[script:example_settings]\nmatch = /example/settings\n")
        write(self.repo, f"{app}/inputs.conf", "[example_advisories]\ninterval = 3600\n\n[example_advisories://splunk_advisories]\n")
        write(self.repo, f"{app}/collections.conf", "[example_findings]\nfield.host = string\n")
        write(self.repo, "ui/src/App.tsx", APP_TSX)
        write(self.repo, "ui/src/App.unit.tsx", '<Heading level={2}>Not a screen</Heading>')
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "0.8.1")
        git(self.repo, "tag", "v0.8.1")
        write(self.repo, f"{app}/app.conf", APP_CONF.format(version="0.9.0", build="2"))
        write(self.repo, f"{app}/data/ui/views/example_trends.xml", "<dashboard><label>Trends</label></dashboard>")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "0.9.0")
        self.config = root / "config"
        self.config.mkdir()
        (self.config / "coverage-sources.json").write_text(json.dumps([
            {"app": "TA-example", "repo": str(self.repo), "path": "TA-example", "ui": {"ui/src": "example_overview"}}]))
        self.store = Store(root / "data")
        self.lab = Lab(FakeSource(), self.store)
        self.lab.discover()
        self.coverage = Coverage(self.store, self.lab, self.config)

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()


class InventoryTest(CoverageFixture):
    def test_the_inventory_comes_from_the_tag_matching_the_installed_version(self):
        found = self.coverage.full_map()
        self.assertEqual(found["errors"], [])
        app = found["apps"][0]
        self.assertEqual(app["source"]["ref"], "v0.8.1")
        self.assertEqual((app["source"]["version"], app["source"]["build"]), ("0.8.1", "1"))
        self.assertEqual(app["default_branch"]["version"], "0.9.0")
        self.assertEqual([(item["component"], item["matches_source"]) for item in app["installed"]],
                         [(component, True) for component in sorted(item["component"] for item in app["installed"])])
        self.assertTrue(app["installed"])
        items = {item["id"]: item for item in app["items"]}
        self.assertNotIn("screen:example_trends", items)  # added after the installed version
        self.assertEqual(items["screen:example_overview"]["label"], "Example Overview")
        self.assertEqual(items["screen:example_overview"]["source"], "TA-example/default/data/ui/views/example_overview.xml:2")
        self.assertEqual(items["screen:example_overview"]["detail"], "in the app menu")
        self.assertEqual(items["screen:example_settings"]["detail"], "not in the app menu")
        self.assertEqual(items["panel:example_overview:Findings by severity"]["parent"], "screen:example_overview")
        self.assertEqual(items["search:Example - Update Findings"]["kind"], "scheduled search")
        self.assertEqual(items["search:Example - Critical Forwarders"]["detail"],
                         "cron 30 7 * * *, alert action, disabled by default")
        self.assertEqual(items["search:Example - Lookup Report"]["kind"], "saved search")
        self.assertNotIn("search:default", items)
        self.assertEqual(items["command:examplecheck"]["source"], "TA-example/default/commands.conf:1")
        self.assertIn("rest:script:example_settings", items)
        self.assertEqual([key for key in items if key.startswith("input:")], ["input:example_advisories://splunk_advisories"])
        self.assertIn("kv:example_findings", items)
        # Page sections drawn by React: each heading once, with its other places; no unit-test files or expressions.
        section = items["section:example_overview:Agency directory"]
        self.assertEqual((section["source"], section["also"]), ("ui/src/App.tsx:3", ["ui/src/App.tsx:5"]))
        self.assertIn("section:example_overview:Edit agency", items)
        self.assertIn("action:example_overview:Save agency", items)
        self.assertFalse(any("Not a screen" in key or "dynamicTitle" in key for key in items))

    def test_without_a_matching_tag_the_default_branch_is_used_and_says_so(self):
        git(self.repo, "tag", "-d", "v0.8.1")
        app = self.coverage.full_map()["apps"][0]
        self.assertEqual(app["source"]["ref"], "main")
        self.assertIn("default branch", app["source_reason"])
        self.assertFalse(app["installed"][0]["matches_source"])
        self.assertIn("screen:example_trends", {item["id"] for item in app["items"]})

    def test_an_untagged_build_on_a_local_branch_is_preferred_to_the_default_branch(self):
        git(self.repo, "tag", "-d", "v0.8.1")
        git(self.repo, "branch", "release-candidate", "HEAD~1")
        app = self.coverage.full_map()["apps"][0]
        self.assertEqual(app["source"]["ref"], "release-candidate")
        self.assertIn("local branch", app["source_reason"])
        self.assertTrue(all(item["matches_source"] for item in app["installed"]))

    def test_a_broken_source_is_reported_without_hiding_the_others(self):
        sources = json.loads((self.config / "coverage-sources.json").read_text())
        sources.append({"app": "missing", "repo": str(self.repo.parent / "nowhere"), "path": "x"})
        (self.config / "coverage-sources.json").write_text(json.dumps(sources))
        found = self.coverage.full_map()
        self.assertEqual([app["app"] for app in found["apps"]], ["TA-example"])
        self.assertEqual(found["errors"][0]["app"], "missing")


class MarksTest(CoverageFixture):
    def test_tested_needs_a_verdict_and_evidence_and_the_latest_mark_wins(self):
        item = "screen:example_overview"
        self.assertEqual(self.coverage.record("TA-example", item, "normal", "tested", verdict="pass"), "unverified")
        self.assertEqual(self.coverage.record("TA-example", item, "normal", "tested", verdict="pass", run_id="r1",
                                              evidence=[3, 4], by="assistant"), "tested")
        self.coverage.record("TA-example", item, "empty", "n/a", note="always has data")
        with self.assertRaises(ValueError):
            self.coverage.record("TA-example", item, "sideways", "tested")
        app = self.coverage.full_map()["apps"][0]
        cases = next(entry for entry in app["items"] if entry["id"] == item)["cases"]
        self.assertEqual((cases["normal"]["verdict"], cases["normal"]["run_id"], cases["normal"]["evidence"]), ("pass", "r1", [3, 4]))
        self.assertEqual(cases["empty"]["status"], "n/a")
        self.assertIsNone(cases["error"])
        self.assertEqual((app["counts"]["pass"], app["counts"]["n/a"]), (1, 1))
        self.assertEqual(sum(app["counts"].values()), len(app["items"]) * 6)


class CoverageApiTest(CoverageFixture):
    def setUp(self):
        super().setUp()
        self.router = start_router()
        self.server = create_server(("127.0.0.1", 0), f"http://127.0.0.1:{self.router.server_port}",
                                    lab=self.lab, store=self.store, coverage=self.coverage)
        start(self.server)
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.router.shutdown()
        self.router.server_close()
        super().tearDown()

    def test_the_page_reads_the_map_and_the_owner_marks_a_case(self):
        status, body = call(self.port, "GET", "/observer/api/coverage")
        self.assertEqual(status, 200)
        self.assertEqual(body["apps"][0]["source"]["ref"], "v0.8.1")
        status, body = call(self.port, "POST", "/observer/api/coverage/marks",
                            {"app": "TA-example", "item": "screen:example_settings", "case": "permission", "status": "n/a"})
        self.assertEqual((status, body["status"]), (200, "n/a"))
        status, _body = call(self.port, "POST", "/observer/api/coverage/marks", {"app": "nope", "item": "x", "case": "normal", "status": "n/a"})
        self.assertEqual(status, 404)
        status, _body = call(self.port, "POST", "/observer/api/coverage/marks",
                             {"app": "TA-example", "item": "x", "case": "normal", "status": "great"})
        self.assertEqual(status, 400)


@unittest.skipIf(assistant_module.anthropic is None, "the anthropic package is not installed")
class CoverageToolsTest(AssistantFixture):
    def setUp(self):
        super().setUp()
        self.fixture = CoverageFixture()
        self.fixture.setUp()
        self.coverage = Coverage(self.store, self.lab, self.fixture.config)
        self.assistant.coverage = self.coverage

    def tearDown(self):
        self.fixture.tearDown()
        super().tearDown()

    def test_versions_show_before_a_walkthrough_and_a_tested_case_is_recorded_with_its_steps(self):
        self.api.script = [
            message([tool_use("t1", "coverage_map", {"app": "TA-example"})], "tool_use"),
            message([tool_use("t2", "propose_walkthrough", {"goal": "Check the overview", "steps": ["Open it"], "apps": ["TA-example"]})], "tool_use"),
            message([tool_use("t3", "record_coverage", {"app": "TA-example", "item": "screen:example_overview", "case": "normal",
                                                        "result": "pass", "evidence_steps": [3, 99], "note": "Lists forwarders"}),
                     tool_use("t4", "record_coverage", {"app": "TA-example", "item": "screen:made_up", "case": "normal",
                                                        "result": "pass", "evidence_steps": [3], "note": ""}),
                     tool_use("t5", "record_coverage", {"app": "TA-example", "item": "screen:example_settings", "case": "error",
                                                        "result": "fail", "evidence_steps": [], "note": "no evidence"})], "tool_use"),
            message([{"type": "text", "text": "Done."}], "end_turn"),
        ]
        run = self.assistant.start("Test the Example overview")
        self.wait(run, lambda current: any(item["type"] == "approval" for item in current.record["events"]))
        approval = next(item for item in run.record["events"] if item["type"] == "approval")
        versions = approval["details"]["versions"][0]
        self.assertEqual((versions["source"]["ref"], versions["source"]["version"]), ("v0.8.1", "0.8.1"))
        self.assertTrue(all(item["matches_source"] for item in versions["installed"]))
        run.decide(approval["approval_id"], "approve")
        self.wait(run, self.finished)

        content = self.api.requests[1]["body"]["messages"][-1]["content"][0]["content"]
        first = json.loads(content if isinstance(content, str) else content[0]["text"])
        self.assertEqual(first["source"]["ref"], "v0.8.1")
        self.assertIn("screen:example_overview", {item["id"] for item in first["items"]})
        results = {item["tool_use_id"]: item for item in self.api.requests[3]["body"]["messages"][-1]["content"]}
        self.assertTrue(results["t4"].get("is_error"))
        marks = {(mark["item"], mark["case"]): mark for mark in self.coverage.marks("TA-example")}
        normal = marks[("screen:example_overview", "normal")]
        self.assertEqual((normal["status"], normal["verdict"], normal["evidence"], normal["run_id"], normal["by"]),
                         ("tested", "pass", [3], run.id, "assistant"))
        self.assertEqual(marks[("screen:example_settings", "error")]["status"], "unverified")
        shown = [item for item in run.record["events"] if item["type"] == "coverage"]
        self.assertEqual([item["result"] for item in shown], ["pass", "unverified"])


if __name__ == "__main__":
    unittest.main()
