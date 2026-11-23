"""Checks: what an app shows compared with an independent reading, run without an AI model."""

import io
import json
import time
import urllib.error

from observer.checks import Checks, load_definitions
from observer.server import create_server
from tests.fakes import start, start_router
from tests.test_coverage import CoverageFixture
from tests.test_discovery_and_history import call

SHOWN = {"what": "what the app shows", "search": {"component": "p-sh1", "app": "TA-example", "query": "| savedsearch \"Shown count\""}, "field": "count"}
EXPECTED = {"what": "Splunk's own list", "search": {"component": "p-sh1", "query": "| rest /services/data/indexes | stats count as value"}, "field": "value"}


def check(**changes):
    return {"id": "shown-count", "title": "The app counts what Splunk lists", "ticket": 15, "app": "TA-example",
            "item": "screen:example_overview", "case": "normal", "shown": SHOWN, "expected": EXPECTED} | changes


class ChecksFixture(CoverageFixture):
    def setUp(self):
        super().setUp()
        self.source = self.lab.source
        self.source.answers = {("p-sh1", "savedsearch"): [{"count": "12"}], ("p-sh1", "| rest"): [{"value": "12"}]}
        self.checks = Checks(self.lab, self.store, self.coverage, self.config, lambda: {"p-sh1": "10.2.4"})

    def define(self, *items):
        (self.config / "checks.json").write_text(json.dumps(list(items)))

    def round(self, ids=None):
        run = self.store.run(self.checks.run_round(ids))
        return run, {item["check"]: item for item in run["events"] if item["type"] == "check"}


class CheckRoundTest(ChecksFixture):
    def test_a_matching_reading_passes_and_marks_the_coverage_case_with_its_steps(self):
        self.define(check())
        run, results = self.round(["shown-count"])
        self.assertEqual(run["origin"], "check")
        self.assertEqual(run["status"], "done")
        self.assertEqual(run["verdict"]["verdict"], "pass")
        self.assertEqual(run["lab_state"], {"p-sh1": "10.2.4"})
        result = results["shown-count"]
        self.assertEqual(result["result"], "pass")
        readings = [item for item in run["events"] if item["type"] == "tool"]
        self.assertEqual([item["seq"] for item in readings], result["evidence_steps"])
        self.assertIn("savedsearch", readings[0]["input"]["search"])
        mark = self.coverage.marks("TA-example")[0]
        self.assertEqual((mark["item"], mark["case"], mark["status"], mark["verdict"], mark["by"], mark["run_id"]),
                         ("screen:example_overview", "normal", "tested", "pass", "scheduled check", run["id"]))
        self.assertEqual(mark["evidence"], result["evidence_steps"])
        self.assertEqual(self.checks.summary()["checks"][-1]["last"]["result"], "pass")

    def test_a_different_reading_fails_and_says_both_values(self):
        self.source.answers[("p-sh1", "| rest")] = [{"value": "13"}]
        self.define(check())
        run, results = self.round(["shown-count"])
        self.assertEqual(results["shown-count"]["result"], "fail")
        self.assertIn("shown 12; expected 13", results["shown-count"]["detail"])
        self.assertEqual(run["verdict"]["verdict"], "fail")
        self.assertEqual(self.coverage.marks("TA-example")[0]["verdict"], "fail")

    def test_a_result_remembers_when_it_changed_and_what_it_was(self):
        self.define(check())
        self.round(["shown-count"])
        first = self.checks.summary()["checks"][-1]["last"]
        self.assertEqual((first["since"], first["was"]), (first["at"], None))
        self.round(["shown-count"])
        again = self.checks.summary()["checks"][-1]["last"]
        self.assertEqual((again["since"], again["was"]), (first["at"], None))
        self.source.answers[("p-sh1", "| rest")] = [{"value": "13"}]
        self.round(["shown-count"])
        failed = self.checks.summary()["checks"][-1]["last"]
        self.assertEqual((failed["result"], failed["was"], failed["since"]), ("fail", "pass", failed["at"]))

    def test_a_reading_that_cannot_be_taken_is_unverified_never_passed(self):
        self.source.answers[("p-sh1", "savedsearch")] = urllib.error.HTTPError(
            "u", 403, "Forbidden", {}, io.BytesIO(b'{"messages": [{"text": "insufficient permission to access this resource"}]}'))
        self.define(check())
        run, results = self.round(["shown-count"])
        self.assertEqual(results["shown-count"]["result"], "unverified")
        self.assertIn("insufficient permission", results["shown-count"]["detail"])
        self.assertEqual(run["verdict"]["verdict"], "inconclusive")
        mark = self.coverage.marks("TA-example")[0]
        self.assertEqual((mark["status"], mark["verdict"]), ("unverified", None))

    def test_an_empty_answer_is_unverified(self):
        self.source.answers[("p-sh1", "savedsearch")] = []
        self.define(check())
        _run, results = self.round(["shown-count"])
        self.assertEqual(results["shown-count"]["result"], "unverified")

    def test_every_member_must_show_the_same_value(self):
        shown = {"what": "members", "search": {"components": ["p-sh1", "p-sh2"], "query": "| makeresults /member"}, "field": "n"}
        self.source.answers[("p-sh1", "/member")] = [{"n": "3"}]
        self.source.answers[("p-sh2", "/member")] = [{"n": "4"}]
        self.define(check(id="members-agree", compare="all_equal", shown=shown, expected=None))
        _run, results = self.round(["members-agree"])
        self.assertEqual(results["members-agree"]["result"], "fail")
        self.source.answers[("p-sh2", "/member")] = [{"n": "3"}]
        _run, results = self.round(["members-agree"])
        self.assertEqual(results["members-agree"]["result"], "pass")

    def test_one_value_per_named_host_is_compared_with_each_hosts_own(self):
        shown = {"what": "recorded", "search": {"component": "p-sh1", "each": ["p-sh1", "p-sh2"], "query": "| inputlookup inv | search host={each}"}, "field": "v"}
        expected = {"what": "own", "search": {"components": ["p-sh1", "p-sh2"], "query": "| makeresults own"}, "field": "v"}
        self.source.answers.update({("p-sh1", "host=p-sh1"): [{"v": "10.2.4"}], ("p-sh1", "host=p-sh2"): [{"v": "9.4.3"}],
                                    ("p-sh1", "makeresults own"): [{"v": "10.2.4"}], ("p-sh2", "makeresults own"): [{"v": "9.4.3"}]})
        self.define(check(id="each-host", compare="each_equal", shown=shown, expected=expected))
        _run, results = self.round(["each-host"])
        self.assertEqual(results["each-host"]["result"], "pass")
        self.source.answers[("p-sh2", "makeresults own")] = [{"v": "10.2.4"}]  # equal to the other host, not to its own record
        _run, results = self.round(["each-host"])
        self.assertEqual(results["each-host"]["result"], "fail")

    def test_a_container_image_version_is_an_independent_reading(self):
        shown = {"what": "recorded", "search": {"component": "p-sh1", "each": ["p-uf"], "query": "| inputlookup fwd | search host={each}"}, "field": "v"}
        self.source.answers[("p-sh1", "host=p-uf")] = [{"v": "10.2.4"}]
        self.define(check(id="fwd-version", compare="each_equal", shown=shown, expected={"what": "image", "image": ["p-uf"]}),
                    check(id="fwd-missing", compare="each_equal", shown=shown, expected={"what": "image", "image": ["p-gone"]}))
        _run, results = self.round(["fwd-version", "fwd-missing"])
        self.assertEqual((results["fwd-version"]["result"], results["fwd-missing"]["result"]), ("pass", "unverified"))

    def test_a_failure_on_a_case_is_not_hidden_by_another_check_that_passes(self):
        failing = dict(EXPECTED, search=dict(EXPECTED["search"], query="| makeresults other"))
        self.source.answers[("p-sh1", "makeresults other")] = [{"value": "99"}]
        self.define(check(id="aa-fails", expected=failing), check(id="zz-passes"))
        self.round(["aa-fails", "zz-passes"])
        mark = self.coverage.marks("TA-example")[0]
        self.assertEqual((mark["verdict"], len(self.coverage.marks("TA-example"))), ("fail", 1))
        self.assertIn("aa-fails", mark["note"])
        self.round(["zz-passes"])  # running only the passing one later still leaves the case failed
        self.assertEqual(self.coverage.marks("TA-example")[0]["verdict"], "fail")

    def test_a_check_that_would_write_is_refused_when_it_is_loaded(self):
        writing = dict(SHOWN, search=dict(SHOWN["search"], query="| makeresults | outputlookup x.csv"))
        self.define(check(shown=writing), check(id="no title", title=""))
        checks, problems = load_definitions(self.config)
        self.assertNotIn("shown-count", [item["id"] for item in checks])
        self.assertTrue(any("may only read" in problem for problem in problems))
        self.assertEqual(len([problem for problem in problems if problem.startswith("checks.json")]), 2)
        run, results = self.round(["shown-count"])
        self.assertEqual(results, {})
        self.assertEqual(self.source.searches if hasattr(self.source, "searches") else [], [])
        self.assertEqual(run["verdict"]["verdict"], "inconclusive")

    def test_the_packaged_checks_all_load(self):
        (self.config / "checks.json").unlink(missing_ok=True)
        checks, problems = load_definitions(self.config)
        self.assertEqual(problems, [])
        self.assertGreaterEqual(len(checks), 1)

    def test_checks_in_the_config_checks_folder_load_with_the_others(self):
        (self.config / "checks").mkdir(exist_ok=True)
        (self.config / "checks" / "mine.json").write_text(json.dumps([check(id="folder-check")]), encoding="utf-8")
        checks, problems = load_definitions(self.config)
        self.assertEqual(problems, [])
        self.assertIn("folder-check", [item["id"] for item in checks])
        self.assertEqual(next(item for item in checks if item["id"] == "folder-check")["file"], "mine.json")

    def test_an_item_the_installed_version_does_not_have_gets_no_mark(self):
        self.define(check(item="screen:example_trends"))
        run, results = self.round(["shown-count"])
        self.assertEqual(results["shown-count"]["result"], "pass")
        self.assertEqual(self.coverage.marks("TA-example"), [])
        self.assertTrue(any("No coverage mark" in item.get("text", "") for item in run["events"]))


class ChecksApiTest(ChecksFixture):
    def setUp(self):
        super().setUp()
        self.define(check())
        self.router = start_router()
        self.server = create_server(("127.0.0.1", 0), f"http://127.0.0.1:{self.router.server_port}",
                                    lab=self.lab, store=self.store, coverage=self.coverage, checks=self.checks)
        start(self.server)
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.router.shutdown()
        self.router.server_close()
        super().tearDown()

    def test_the_owner_runs_one_check_and_reads_its_result(self):
        status, body = call(self.port, "GET", "/observer/api/checks")
        self.assertEqual(status, 200)
        mine = next(item for item in body["checks"] if item["id"] == "shown-count")
        self.assertIsNone(mine["last"])
        self.assertEqual(body["account"], "lab_observer")
        status, body = call(self.port, "POST", "/observer/api/checks/run", {"ids": ["shown-count"]})
        self.assertEqual((status, body), (202, {"started": True}))
        deadline = time.time() + 5
        while time.time() < deadline:
            _status, body = call(self.port, "GET", "/observer/api/checks")
            mine = next(item for item in body["checks"] if item["id"] == "shown-count")
            if mine["last"] and not body["status"]["running"]:
                break
            time.sleep(0.05)
        self.assertEqual(mine["last"]["result"], "pass")
        self.assertTrue(mine["last"]["run_id"])

