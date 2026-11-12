"""A fixture run for Hindsight's asset context and exceptions (issue #13).

The lab holds no asset context and no exceptions, so those features cannot be checked by reading
alone. This run adds one of each through Hindsight's own REST handler as the lab_operator account,
reads what the app then shows as the read-only account, takes them out again, and reads once more.
Every step is kept as a run in the observer, and each case is marked on the coverage map.

It changes the lab, so it runs only when the owner has approved it:

    python -m observer.fixture_hindsight --approved-by-owner

The fixture rows are removed in every outcome, including a failure half way.
"""

import argparse
import base64
import datetime
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from observer.assistant import Run
from observer.coverage import Coverage
from observer.lab import DEFAULT_SPLUNK_CONFIG, Lab, PodmanSplunkSource
from observer.server import DEFAULT_CONFIG_DIR
from observer.store import DEFAULT_DATA_DIR, Store

APP = "TA-hindsight"
COMPONENT = "p-mgmt"
HOST = "p-fwd-uf-9-0-10"
OWNER, UNIT, CRITICALITY = "observer-fixture-owner", "observer-fixture-unit", "high"
REASON = "Observer fixture: temporary exception to check that Hindsight applies and withdraws it"
FINDINGS = ('| inputlookup hindsight_findings | search hostname="%s" hindsight_status=vulnerable '
            '| eval vuln_id=if(match(cve, "^CVE-[0-9]+-[0-9]+$"), cve, svd) ' % HOST)
CONTEXT = ('| inputlookup hindsight_forwarder_inventory | search hostname="%s" | head 1 | `hindsight_asset_context` '
           '| fillnull value="" asset_owner asset_business_unit asset_criticality '
           '| fields asset_owner asset_business_unit asset_criticality' % HOST)


class Fixture:
    def __init__(self, config_dir, data_dir):
        self.store = Store(data_dir)
        self.source = PodmanSplunkSource()
        self.coverage = Coverage(self.store, Lab(self.source, self.store), config_dir)
        operator = json.loads((Path(config_dir) / "operator.json").read_text())
        reader = json.loads(Path(DEFAULT_SPLUNK_CONFIG).read_text())
        self.router = operator.get("router", "http://127.0.0.1:8190").rstrip("/")
        self.accounts = {account["username"]: "Basic " + base64.b64encode(f"{account['username']}:{account['password']}".encode()).decode()
                         for account in (operator, reader)}
        self.operator, self.reader = operator["username"], reader["username"]
        self.run = Run(self.store, "Fixture: Hindsight asset context and exceptions (issue #13)")
        self.run.record.update(origin="terminal", model="no AI model: a scripted fixture run", accounts=[self.operator, self.reader])
        self.run.event("prompt", text=self.run.record["title"])
        self.results = []

    # --- steps ----------------------------------------------------------------------

    def call(self, account, method, path, body=None, why=""):
        """One request to Hindsight's handler or splunkd on p-mgmt; a step of the run. Returns (status, reply)."""
        request = urllib.request.Request(f"{self.router}/mgmt/{COMPONENT}{path}?output_mode=json", method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Authorization": self.accounts[account], "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                status, text = response.status, response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            status, text = error.code, error.read().decode("utf-8", errors="replace")
        try:
            reply = json.loads(text or "{}")
        except ValueError:
            reply = {"text": text[:300]}
        shown = {key: reply[key] for key in ("message", "error", "messages") if isinstance(reply, dict) and key in reply} or \
            (reply if isinstance(reply, dict) and len(text) < 600 else {"bytes": len(text)})
        item = self.run.event("tool", name=f"{method} {path}", input={"as": account, "body": body, "why": why},
                              source=f"splunkd {COMPONENT} as {account}", status="ok" if status < 400 else "error",
                              result=f"HTTP {status} {json.dumps(shown)[:600]}")
        return status, reply, item["seq"]

    def read(self, what, query):
        """One search as the read-only account; a step of the run. Returns (first row or {}, step)."""
        rows, source = self.source.splunk_search(COMPONENT, query, "-24h", "now", 5, app=APP)
        row = {key: value for key, value in (rows[0] if rows else {}).items() if not key.startswith("_")}
        item = self.run.event("tool", name="fixture reading", input={"reading": what, "search": query, "app": APP},
                              source=source, status="ok", result=json.dumps(row))
        return row, item["seq"]

    def verdict(self, title, item, case, passed, detail, steps):
        result = "pass" if passed else "fail"
        self.results.append((title, result, detail))
        self.run.event("check", check=f"fixture:{item}:{case}", title=title, result=result, detail=detail, evidence_steps=steps, ticket=13)
        self.coverage.record(APP, item, case, "tested", verdict=result, run_id=self.run.id, evidence=steps,
                             note=f"fixture run: {detail}"[:500], by="fixture run")
        self.run.event("coverage", app=APP, item=item, case=case, result=result, evidence_steps=steps, note=title)

    def findings(self, what):
        return self.read(what, FINDINGS + '| `hindsight_exceptions(guid)` | stats count as all count(exception) as excepted values(exception) as label '
                                          '| eval label=coalesce(mvjoin(label, ","), "")')

    # --- the run ----------------------------------------------------------------------

    def go(self):
        key = None
        try:
            target, s0 = self.read("the host's GUID and one of its vulnerabilities, from the findings",
                                   FINDINGS + "| stats count as rows by guid vuln_id | sort vuln_id | head 1")
            guid, vuln, covered = target["guid"], target["vuln_id"], int(target["rows"])
            before, s1 = self.findings("findings for the host before the fixture")
            context_before, s2 = self.read("asset context for the host before the fixture", CONTEXT)
            clean = int(before["excepted"]) == 0 and not context_before.get("asset_owner")
            self.verdict("With no exceptions and no asset context, no finding is excepted and no owner is shown",
                         "kv:hindsight_exceptions", "empty", clean,
                         f"{before['all']} findings, {before['excepted']} excepted; owner {context_before.get('asset_owner')!r}", [s1, s2])
            if not clean:
                raise RuntimeError("The host already has an exception or asset context; not touching it")

            # Asset context: bad input, no permission, then the real row.
            status, _reply, s = self.call(self.operator, "POST", "/services/hindsight/context",
                                          {"rows": [{"host": HOST, "owner": OWNER, "criticality": "urgent"}]}, "a criticality the app does not allow")
            after_bad, s_bad = self.read("asset context after the refused row", CONTEXT)
            self.verdict("A row with a criticality that is not allowed is refused and nothing is saved", "kv:hindsight_asset_context", "incorrect",
                         status == 400 and not after_bad.get("asset_owner"), f"HTTP {status}; owner {after_bad.get('asset_owner')!r}", [s, s_bad])
            row = {"host": HOST, "owner": OWNER, "business_unit": UNIT, "criticality": CRITICALITY}
            status, _reply, s = self.call(self.reader, "POST", "/services/hindsight/context", {"rows": [row]}, "the read-only account must not be able to save")
            after_denied, s_denied = self.read("asset context after the read-only account tried", CONTEXT)
            self.verdict("The read-only account cannot save asset context", "kv:hindsight_asset_context", "permission",
                         status in {401, 403, 404} and not after_denied.get("asset_owner"), f"HTTP {status}; owner {after_denied.get('asset_owner')!r}", [s, s_denied])
            status, _reply, s = self.call(self.operator, "POST", "/services/hindsight/context", {"rows": [row]}, "the fixture row")
            shown, s_shown = self.read("asset context the app shows for the host", CONTEXT)
            self.verdict("The owner, business unit and criticality saved for a host are the ones shown for it", "kv:hindsight_asset_context", "normal",
                         status == 200 and (shown.get("asset_owner"), shown.get("asset_business_unit"), shown.get("asset_criticality")) == (OWNER, UNIT, CRITICALITY),
                         f"saved {OWNER}/{UNIT}/{CRITICALITY}; shown {shown.get('asset_owner')}/{shown.get('asset_business_unit')}/{shown.get('asset_criticality')}", [s, s_shown])

            # Exceptions: bad input, no permission, then the real one.
            expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).strftime("%Y-%m-%d")
            body = {"asset": guid, "vuln_id": vuln, "kind": "accepted", "reason": REASON, "expires": expires}
            status, _reply, s = self.call(self.operator, "POST", "/services/hindsight/exceptions", body | {"vuln_id": "NOT-A-CVE"}, "an identifier that is not a CVE or SVD")
            after_bad, s_bad = self.findings("findings after the refused exception")
            self.verdict("An exception for something that is not a CVE or SVD is refused and nothing is excepted", "kv:hindsight_exceptions", "incorrect",
                         status == 400 and int(after_bad["excepted"]) == 0, f"HTTP {status}; {after_bad['excepted']} excepted", [s, s_bad])
            status, _reply, s = self.call(self.reader, "POST", "/services/hindsight/exceptions", body, "the read-only account must not be able to save")
            after_denied, s_denied = self.findings("findings after the read-only account tried")
            self.verdict("The read-only account cannot create an exception", "kv:hindsight_exceptions", "permission",
                         status in {401, 403, 404} and int(after_denied["excepted"]) == 0, f"HTTP {status}; {after_denied['excepted']} excepted", [s, s_denied])
            status, reply, s = self.call(self.operator, "POST", "/services/hindsight/exceptions", body, "the fixture exception")
            key = (reply.get("exception") or {}).get("_key")
            applied, s_applied = self.findings("findings with the exception in place")
            self.verdict(f"An exception for {vuln} on the host marks exactly that host's findings for it, as Risk accepted", "kv:hindsight_exceptions", "normal",
                         status == 200 and int(applied["excepted"]) == covered and applied["label"] == "Risk accepted" and applied["all"] == before["all"],
                         f"{covered} finding(s) for {vuln}; {applied['excepted']} of {applied['all']} shown as {applied['label']!r}", [s0, s, s_applied])

            # Recovery: revoke, and take the context row out.
            status, _reply, s = self.call(self.operator, "POST", "/services/hindsight/exceptions/revoke", {"key": key}, "revoke the fixture exception")
            revoked, s_revoked = self.findings("findings after the exception was revoked")
            self.verdict("Revoking the exception shows the findings as open again", "kv:hindsight_exceptions", "recovery",
                         status == 200 and int(revoked["excepted"]) == 0 and revoked["all"] == before["all"],
                         f"HTTP {status}; {revoked['excepted']} of {revoked['all']} excepted", [s, s_revoked])
            status, _reply, s = self.call(self.operator, "POST", "/services/hindsight/context", {"delete": [HOST]}, "remove the fixture row")
            removed, s_removed = self.read("asset context after the row was removed", CONTEXT)
            self.verdict("Removing a host's asset context stops it being shown", "kv:hindsight_asset_context", "recovery",
                         status == 200 and not removed.get("asset_owner"), f"HTTP {status}; owner {removed.get('asset_owner')!r}", [s, s_removed])
        except Exception as error:  # the run records what stopped it; cleanup still happens
            self.run.event("error", text=f"The fixture run stopped: {error.__class__.__name__}: {str(error)[:300]}")
            self.results.append(("the run completed", "fail", str(error)[:200]))
        finally:
            self.cleanup(key)

    def cleanup(self, key):
        """Take out everything this run could have added, and say what is left."""
        self.call(self.operator, "POST", "/services/hindsight/context", {"delete": [HOST]}, "cleanup: the fixture row, if it is still there")
        if key:  # a revoked exception is kept by the app as a record; the fixture's own record is removed
            self.call(self.operator, "DELETE", f"/servicesNS/nobody/{APP}/storage/collections/data/hindsight_exceptions/{key}", None,
                      "cleanup: the fixture's revoked exception record")
        left, step = self.read("what is left of the fixture", '| inputlookup hindsight_exceptions | search reason="Observer fixture*" | stats count as exceptions '
                               '| appendcols [| inputlookup hindsight_asset_context | search owner="%s" | stats count as context]' % OWNER)
        clean = left.get("exceptions") == "0" and left.get("context") == "0"
        self.run.event("text", text="Cleanup: no fixture rows are left." if clean else f"Cleanup incomplete: {left}")
        failed = [title for title, result, _detail in self.results if result == "fail"]
        verdict = "fail" if failed or not clean else "pass"
        self.run.record["verdict"] = {"verdict": verdict, "evidence_steps": [step], "summary":
                                      f"{len(self.results) - len(failed)} of {len(self.results)} cases passed; cleanup {'complete' if clean else 'INCOMPLETE'}."}
        self.run.event("verdict", **self.run.record["verdict"])
        self.run.set_status("done")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--approved-by-owner", action="store_true", help="The owner approved this change to the lab")
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    args = parser.parse_args()
    if not args.approved_by_owner:
        sys.exit("This run adds and removes rows in Hindsight on the lab. Run it with --approved-by-owner once the owner has agreed.")
    fixture = Fixture(args.config_dir, args.data_dir)
    fixture.go()
    for title, result, detail in fixture.results:
        print(f"{result:5} {title}: {detail}")
    print("run", fixture.run.id, fixture.run.record["verdict"]["summary"])


if __name__ == "__main__":
    main()
