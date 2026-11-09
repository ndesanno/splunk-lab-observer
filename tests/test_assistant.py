"""Claude runs against a fake Messages API: audited tools, shown screens, and approval-gated changes."""

import json
import os
import stat
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from observer import assistant as assistant_module
from observer.assistant import Assistant
from observer.lab import Lab
from observer.server import create_server
from observer.store import Store
from tests.fakes import FakeSource, start, start_router
from tests.test_discovery_and_history import call

KEY = "sk-ant-test-key-0000000000000000"


def message(content, stop_reason):
    return {"id": f"msg_{time.time_ns()}", "type": "message", "role": "assistant", "model": assistant_module.MODEL,
            "content": content, "stop_reason": stop_reason, "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 20}}


def tool_use(tool_id, name, arguments):
    return {"type": "tool_use", "id": tool_id, "name": name, "input": arguments}


class FakeMessagesApi(BaseHTTPRequestHandler):
    """Answers POST /v1/messages from a script and keeps every request body it was sent."""

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append({"headers": dict(self.headers), "body": body})
        reply = json.dumps(self.server.script.pop(0)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_args):
        pass


class AssistantFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.source = FakeSource()
        self.lab = Lab(self.source, self.store)
        self.lab.discover()
        self.api = ThreadingHTTPServer(("127.0.0.1", 0), FakeMessagesApi)
        self.api.requests, self.api.script = [], []
        start(self.api)
        self.saved_base_url = os.environ.get("ANTHROPIC_BASE_URL")
        os.environ["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{self.api.server_port}"
        self.assistant = Assistant(self.lab, self.store, self.temp.name)
        self.assistant.key.save(KEY)

    def tearDown(self):
        if self.saved_base_url is None:
            os.environ.pop("ANTHROPIC_BASE_URL", None)
        else:
            os.environ["ANTHROPIC_BASE_URL"] = self.saved_base_url
        self.api.shutdown()
        self.api.server_close()
        self.store.db.close()
        self.temp.cleanup()

    def wait(self, run, predicate, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate(run):
                return
            time.sleep(0.05)
        self.fail(f"timed out; events: {json.dumps(run.record['events'], indent=1)[:3000]}")

    def finished(self, run):
        return run.record["status"] in {"done", "failed", "stopped"}


@unittest.skipIf(assistant_module.anthropic is None, "the anthropic package is not installed")
class AssistantRunTest(AssistantFixture):
    def test_read_only_run_records_evidence_shows_screens_and_keeps_raw_events_local(self):
        self.api.script = [
            message([{"type": "text", "text": "Opening Hindsight."},
                     tool_use("t1", "show_screen", {"component": "p-sh1", "path": "/en-US/app/TA-hindsight/hindsight_overview"}),
                     tool_use("t2", "run_search", {"component": "p-sh1", "query": "index=_internal ERROR"}),
                     tool_use("t3", "run_search", {"component": "p-sh1", "query": "index=_internal ERROR | stats count by component"}),
                     tool_use("t4", "splunk_rest_get", {"component": "p-sh1", "path": "/services/storage/passwords"}),
                     tool_use("t5", "container_logs", {"component": "p-uf"})], "tool_use"),
            message([{"type": "text", "text": "TailReader logged 3 errors (run_search on p-sh1)."}], "end_turn"),
        ]
        run = self.assistant.start("What is failing on p-sh1?")
        self.wait(run, self.finished)
        self.assertEqual(run.record["status"], "done")

        first = self.api.requests[0]["body"]
        self.assertEqual(first["model"], "claude-opus-5-5")
        self.assertEqual(first["thinking"], {"type": "adaptive", "display": "summarized"})
        self.assertEqual(first["output_config"], {"effort": "medium"})
        self.assertEqual(first["fallbacks"], "default")
        self.assertIn("server-side-fallback-2026-07-01", self.api.requests[0]["headers"].get("anthropic-beta", ""))
        self.assertNotIn("tool_choice", first)

        # All five results return together in one user message, in call order.
        results = self.api.requests[1]["body"]["messages"][-1]
        self.assertEqual(results["role"], "user")
        self.assertEqual([item["tool_use_id"] for item in results["content"]], ["t1", "t2", "t3", "t4", "t5"])
        by_id = {item["tool_use_id"]: item for item in results["content"]}
        self.assertTrue(by_id["t2"].get("is_error"))
        self.assertTrue(by_id["t4"].get("is_error"))
        self.assertFalse(by_id["t3"].get("is_error"))
        self.assertEqual(self.source.searches, ["search index=_internal ERROR | stats count by component"])

        sent = json.dumps([request["body"] for request in self.api.requests])
        self.assertNotIn("raw event text", sent)
        self.assertNotIn("hunter2", sent)
        self.assertNotIn(KEY, sent)

        events = run.record["events"]
        display = [item for item in events if item["type"] == "display"]
        self.assertEqual(display[0]["component"], "p-sh1")
        self.assertEqual(display[0]["path"], "/en-US/app/TA-hindsight/hindsight_overview")
        tools = [item for item in events if item["type"] == "tool"]
        self.assertEqual([item["status"] for item in tools], ["ok", "error", "ok", "error", "ok"])
        search = tools[2]
        self.assertEqual(search["source"], "splunkd p-sh1 oneshot search as lab_observer")
        self.assertIn("TailReader", search["result"])  # the evidence the owner can inspect is what was sent
        self.assertIn(search["result"], sent.replace('\\"', '"'))
        self.assertEqual(run.record["accounts"], ["lab_observer"])
        self.assertEqual(self.store.run(run.id)["status"], "done")

    def test_a_change_waits_for_approval_and_an_unrestored_stop_is_reported(self):
        self.api.script = [
            message([tool_use("t1", "container_action", {"component": "p-idx1", "action": "stop", "reason": "Test failover",
                                                         "expected_effect": "p-idx1 goes down", "cleanup": "start p-idx1"})], "tool_use"),
            message([{"type": "text", "text": "p-idx1 is stopped."}], "end_turn"),
        ]
        run = self.assistant.start("Stop p-idx1 to test failover")
        self.wait(run, lambda item: item.record["status"] == "waiting_for_approval")
        state = lambda: next(item["state"] for item in self.source.container_list if item["name"] == "p-idx1")
        self.assertEqual(state(), "running")  # nothing happens before the owner decides
        approval = next(item for item in run.record["events"] if item["type"] == "approval")
        self.assertEqual(approval["details"]["cleanup"], "start p-idx1")
        self.assertFalse(run.decide(approval["approval_id"], "maybe"))
        self.assertTrue(run.decide(approval["approval_id"], "approve"))
        self.wait(run, self.finished)
        self.assertEqual(state(), "exited")
        summary = next(item for item in run.record["events"] if item["type"] == "summary")
        self.assertEqual(summary["changes"][0]["before"], "running")
        self.assertEqual(summary["changes"][0]["after"], "exited")
        self.assertIn("p-idx1 is still stopped", summary["unresolved"][0])
        self.assertEqual(self.store.latest("p-idx1", "assistant_action")["value"]["action"], "stop")

    def test_a_declined_change_is_not_made_and_claude_hears_why(self):
        self.api.script = [
            message([tool_use("t1", "container_action", {"component": "p-cm", "action": "restart", "reason": "r",
                                                         "expected_effect": "e", "cleanup": "none needed"})], "tool_use"),
            message([{"type": "text", "text": "Understood."}], "end_turn"),
        ]
        run = self.assistant.start("Restart the manager")
        self.wait(run, lambda item: item.record["status"] == "waiting_for_approval")
        approval = next(item for item in run.record["events"] if item["type"] == "approval")
        run.decide(approval["approval_id"], "deny", "Not during the test")
        self.wait(run, self.finished)
        result = self.api.requests[1]["body"]["messages"][-1]["content"][0]
        self.assertTrue(result["is_error"])
        self.assertIn("declined", json.dumps(result["content"]))
        self.assertIn("Not during the test", json.dumps(result["content"]))
        self.assertFalse(self.store.latest("p-cm", "assistant_action"))

    def test_stop_ends_a_run_waiting_for_approval_without_the_change(self):
        self.api.script = [message([tool_use("t1", "container_action", {"component": "p-sh2", "action": "stop", "reason": "r",
                                                                        "expected_effect": "e", "cleanup": "start"})], "tool_use")]
        run = self.assistant.start("Stop p-sh2")
        self.wait(run, lambda item: item.record["status"] == "waiting_for_approval")
        self.assistant.stop(run.id)
        self.wait(run, self.finished)
        self.assertEqual(run.record["status"], "stopped")
        self.assertEqual(len(self.api.requests), 1)
        self.assertEqual(next(item for item in run.record["events"] if item["type"] == "approval")["decision"], "stopped")

    def test_a_follow_up_continues_the_same_conversation(self):
        self.api.script = [message([{"type": "text", "text": "Six components."}], "end_turn"),
                           message([{"type": "text", "text": "p-cm manages p-idx1."}], "end_turn")]
        run = self.assistant.start("How many components?")
        self.wait(run, self.finished)
        self.assistant.start("Which manages which?", run_id=run.id)
        self.wait(run, lambda item: self.finished(item) and len(self.api.requests) == 2)
        messages = self.api.requests[1]["body"]["messages"]
        self.assertEqual([item["role"] for item in messages], ["user", "assistant", "user"])
        self.assertEqual(messages[-1]["content"], "Which manages which?")


class FakeOperator:
    username = "lab_operator"

    def __init__(self):
        self.requests = []

    def request(self, component, method, path, params):
        self.requests.append((component, method, path, params))
        return 201, {"entry": [{"name": params.get("name"), "content": {"maxTotalDataSizeMB": "100", "pass4SymmKey": "s3cret"}}]}


@unittest.skipIf(assistant_module.anthropic is None, "the anthropic package is not installed")
class SplunkChangeTest(AssistantFixture):
    def setUp(self):
        super().setUp()
        self.operator = FakeOperator()
        self.assistant.operator = self.operator

    def test_an_approved_splunk_change_uses_the_operator_account_and_masks_secrets(self):
        self.api.script = [
            message([tool_use("t1", "splunk_change", {"component": "p-cm", "method": "POST", "path": "/services/storage/passwords",
                                                      "params": {"name": "x"}, "reason": "r", "expected_effect": "e", "cleanup": "c"}),
                     tool_use("t2", "splunk_change", {"component": "p-cm", "method": "POST", "path": "/services/data/indexes",
                                                      "params": {"name": "test_fixture_idx", "maxTotalDataSizeMB": "100"},
                                                      "reason": "Fixture for a retention test", "expected_effect": "New index",
                                                      "cleanup": "DELETE /services/data/indexes/test_fixture_idx"})], "tool_use"),
            message([{"type": "text", "text": "Created."}], "end_turn"),
        ]
        run = self.assistant.start("Create a small test index on p-cm")
        self.wait(run, lambda item: item.record["status"] == "waiting_for_approval")
        approvals = [item for item in run.record["events"] if item["type"] == "approval"]
        self.assertEqual(len(approvals), 1)  # the blocked path never reached the owner
        self.assertEqual(approvals[0]["action"], "POST /services/data/indexes on p-cm as lab_operator")
        self.assertEqual(self.operator.requests, [])
        run.decide(approvals[0]["approval_id"], "approve")
        self.wait(run, self.finished)
        self.assertEqual(self.operator.requests, [("p-cm", "POST", "/services/data/indexes",
                                                   {"name": "test_fixture_idx", "maxTotalDataSizeMB": "100"})])
        results = {item["tool_use_id"]: item for item in self.api.requests[1]["body"]["messages"][-1]["content"]}
        self.assertTrue(results["t1"]["is_error"])
        self.assertNotIn("s3cret", json.dumps(self.api.requests[1]["body"]))
        self.assertIn("lab_operator", run.record["accounts"])
        summary = next(item for item in run.record["events"] if item["type"] == "summary")
        self.assertEqual(summary["changes"][0]["cleanup"], "DELETE /services/data/indexes/test_fixture_idx")
        self.assertEqual(self.assistant.status()["change_account"], "lab_operator")

    def test_without_an_operator_account_claude_has_no_splunk_change_tool(self):
        self.assistant.operator = None
        self.api.script = [message([{"type": "text", "text": "ok"}], "end_turn")]
        run = self.assistant.start("hi")
        self.wait(run, self.finished)
        names = [tool["name"] for tool in self.api.requests[0]["body"]["tools"]]
        self.assertNotIn("splunk_change", names)
        self.assertIn("container_action", names)


class AssistantApiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.lab = Lab(FakeSource(), self.store)
        self.lab.discover()
        self.assistant = Assistant(self.lab, self.store, self.temp.name)
        self.router = start_router()
        self.saved_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        self.server = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{self.router.server_port}",
                                          lab=self.lab, store=self.store, assistant=self.assistant))
        self.port = self.server.server_port

    def tearDown(self):
        if self.saved_key is not None:
            os.environ["ANTHROPIC_API_KEY"] = self.saved_key
        self.server.shutdown()
        self.server.server_close()
        self.router.shutdown()
        self.router.server_close()
        self.store.db.close()
        self.temp.cleanup()

    def test_the_key_is_saved_privately_and_never_returned(self):
        status, body = call(self.port, "GET", "/observer/api/assistant")
        self.assertFalse(body["status"]["configured"])
        status, body = call(self.port, "POST", "/observer/api/assistant/runs", {"prompt": "hi"})
        self.assertEqual(status, 400)
        status, body = call(self.port, "POST", "/observer/api/assistant/key", {"api_key": "short"})
        self.assertEqual(status, 400)
        status, body = call(self.port, "POST", "/observer/api/assistant/key", {"api_key": KEY})
        self.assertEqual(status, 200)
        self.assertTrue(body["status"]["configured"])
        self.assertNotIn(KEY, json.dumps(body))
        self.assertEqual(stat.S_IMODE(os.stat(self.assistant.key.path).st_mode), 0o600)
        status, body = call(self.port, "GET", "/observer/api/assistant")
        self.assertNotIn(KEY, json.dumps(body))
        call(self.port, "POST", "/observer/api/assistant/key", {"api_key": ""})
        self.assertFalse(self.assistant.key.path.exists())

    def test_unknown_runs_and_approvals_are_refused(self):
        self.assertEqual(call(self.port, "GET", "/observer/api/assistant/runs/nope")[0], 404)
        self.assertEqual(call(self.port, "POST", "/observer/api/assistant/runs/nope/approvals/x", {"decision": "approve"})[0], 409)


if __name__ == "__main__":
    unittest.main()


class TerminalSessionTest(unittest.TestCase):
    """Claude Code's terminal work appears as a run the page can follow."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.lab = Lab(FakeSource(), self.store)
        self.lab.discover()
        self.store.record("p-sh1", "container", "podman ps", {"state": "running"})
        self.store.record("p-sh1", "web", "router", {"http_status": 200})
        self.store.record("p-uf", "container", "podman ps", {"state": "running"})

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def terminal(self, *argv):
        from observer.terminal import main
        return main(["--data-dir", self.temp.name, *argv])

    def test_a_session_records_screens_notes_and_actions(self):
        self.assertEqual(self.terminal("note", "too early"), 1)
        self.assertEqual(self.terminal("start", "Check the search heads"), 0)
        latest = self.store.latest_run()
        self.assertEqual((latest["status"], latest["origin"]), ("running", "terminal"))
        self.assertEqual(self.terminal("show", "p-sh1", "/en-US/manager/system/clustering"), 0)
        self.assertEqual(self.terminal("show", "p-uf"), 0)
        self.assertEqual(self.terminal("show", "p-uf", "/en-US/app/search"), 1)  # no Splunk Web
        self.assertEqual(self.terminal("show", "p-nope"), 1)
        self.terminal("did", "podman restart p-sh2", "--result", "running")
        self.terminal("note", "Captain is p-sh1.")
        self.terminal("end", "Done.")
        record = self.store.run(latest["id"])
        self.assertEqual(record["status"], "done")
        self.assertEqual([item["type"] for item in record["events"]], ["prompt", "display", "display", "tool", "text", "text"])
        self.assertEqual(record["events"][1]["path"], "/en-US/manager/system/clustering")
        self.assertEqual(record["events"][2]["path"], "")
        self.assertEqual(record["events"][3]["input"], {"action": "podman restart p-sh2"})
        self.assertEqual([item["rev"] for item in record["events"]], sorted({item["rev"] for item in record["events"]}))

    def test_the_page_can_follow_it_but_not_continue_it_with_the_api(self):
        self.terminal("start", "Live work")
        router = start_router()
        server = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{router.server_port}", lab=self.lab, store=self.store,
                                     assistant=Assistant(self.lab, self.store, self.temp.name)))
        try:
            status, body = call(server.server_port, "GET", "/observer/api/assistant/live")
            self.assertEqual(body["latest"]["origin"], "terminal")
            run_id = body["latest"]["id"]
            self.terminal("show", "p-sh1")
            status, body = call(server.server_port, "GET", f"/observer/api/assistant/runs/{run_id}?since=1")
            self.assertEqual([item["type"] for item in body["events"]], ["display"])
            self.assertEqual(body["origin"], "terminal")
            self.terminal("end")
            self.assistant_key(server)
            status, body = call(server.server_port, "POST", f"/observer/api/assistant/runs/{run_id}/messages", {"prompt": "more"})
            self.assertEqual(status, 400)
        finally:
            server.shutdown(); server.server_close(); router.shutdown(); router.server_close()

    def assistant_key(self, server):
        server.assistant.key.save(KEY)


@unittest.skipIf(assistant_module.anthropic is None, "the anthropic package is not installed")
class SharedViewTest(AssistantFixture):
    """Claude reads and acts in the owner's live view through the open page; risky clicks need approval."""

    SCREEN = {"url": "/en-US/app/search/search", "title": "Search", "text": "Search & Reporting", "summary": "Search",
              "omitted": "2 raw event(s) on screen were left out",
              "elements": [{"ref": "e1", "role": "link", "label": "Datasets", "href": "/en-US/app/search/datasets"},
                           {"ref": "e2", "role": "button", "label": "Save As", "type": ""},
                           {"ref": "e3", "role": "password field", "label": "Password", "type": "password", "value": "(hidden)"},
                           {"ref": "e4", "role": "text field", "label": "Name", "type": "text", "in_form": True}]}

    def page(self, run, answers):
        """Act as the owner's open page: keep polling, answer each request in turn."""
        stop = threading.Event()

        def loop():
            handled = set()
            while not stop.is_set():
                run.page_seen = time.time()
                for item in list(run.record["events"]):
                    if item["type"] == "browser" and item["status"] == "pending" and item["request_id"] not in handled:
                        handled.add(item["request_id"])
                        answers.append((item["action"], item["payload"]))
                        run.page_result(item["request_id"], True, dict(self.SCREEN))
                time.sleep(0.02)
        threading.Thread(target=loop, daemon=True).start()
        return stop

    def test_walkthrough_reads_clicks_and_waits_at_checkpoints(self):
        self.api.script = [
            message([tool_use("t1", "propose_walkthrough", {"goal": "Open datasets", "steps": ["Read the search page", "Open Datasets"]})], "tool_use"),
            message([tool_use("t2", "read_screen", {"component": "p-sh1"})], "tool_use"),
            message([tool_use("t3", "click", {"component": "p-sh1", "ref": "e1", "why": "Open Datasets"}),
                     tool_use("t4", "type_text", {"component": "p-sh1", "ref": "e3", "text": "x", "why": "no"})], "tool_use"),
            message([tool_use("t5", "checkpoint", {"step_done": "Open Datasets", "observed": "Datasets list", "next_step": ""})], "tool_use"),
            message([{"type": "text", "text": "Done."}], "end_turn"),
        ]
        run = self.assistant.start("Walk me through datasets")
        answers = []
        stop = self.page(run, answers)
        try:
            self.wait(run, lambda item: item.record["status"] == "waiting_for_approval")
            plan = next(item for item in run.record["events"] if item["type"] == "approval")
            self.assertEqual((plan["kind"], plan["details"]["steps"]), ("plan", ["Read the search page", "Open Datasets"]))
            self.assertEqual(answers, [])  # nothing happens in the view before the owner starts
            run.decide(plan["approval_id"], "approve")
            self.wait(run, lambda item: any(e["type"] == "approval" and e.get("kind") == "checkpoint" for e in item.record["events"]))
            self.assertEqual([action for action, _ in answers], ["read", "click"])  # the password field was refused
            checkpoint = next(item for item in run.record["events"] if item.get("kind") == "checkpoint")
            run.decide(checkpoint["approval_id"], "approve")
            self.wait(run, self.finished)
        finally:
            stop.set()
        self.assertEqual(run.record["status"], "done")
        results = {item["tool_use_id"]: item for item in self.api.requests[2]["body"]["messages"][-1]["content"]}
        reading = json.dumps(results)
        self.assertIn("[e1] link 'Datasets'", reading)
        self.assertIn("raw event(s) on screen were left out", reading)
        results = {item["tool_use_id"]: item for item in self.api.requests[3]["body"]["messages"][-1]["content"]}
        self.assertFalse(results["t3"].get("is_error"))
        self.assertTrue(results["t4"]["is_error"])
        self.assertEqual([e["action"] for e in run.record["events"] if e["type"] == "browser"], ["read", "click"])

    def test_a_save_click_needs_approval_and_a_closed_page_is_reported(self):
        self.api.script = [
            message([tool_use("t1", "read_screen", {"component": "p-sh1"})], "tool_use"),
            message([tool_use("t2", "click", {"component": "p-sh1", "ref": "e2", "why": "Save the search"})], "tool_use"),
            message([tool_use("t3", "read_screen", {"component": "p-sh1"})], "tool_use"),
            message([{"type": "text", "text": "ok"}], "end_turn"),
        ]
        run = self.assistant.start("Save this search")
        answers = []
        stop = self.page(run, answers)
        try:
            self.wait(run, lambda item: item.record["status"] == "waiting_for_approval")
            approval = next(item for item in run.record["events"] if item["type"] == "approval")
            self.assertIn("Save As", approval["action"])
            self.assertEqual([action for action, _ in answers], ["read"])
            stop.set()  # the owner closes the page, then declines from another tab
            run.page_seen = 0
            run.decide(approval["approval_id"], "deny")
            self.wait(run, self.finished)
        finally:
            stop.set()
        self.assertEqual([action for action, _ in answers], ["read"])
        last = self.api.requests[3]["body"]["messages"][-1]["content"][0]
        self.assertTrue(last["is_error"])
        self.assertIn("not open", json.dumps(last["content"]))
