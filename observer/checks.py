"""Checks: a displayed or reported value compared with an independent source, without an AI model.

A check is data (a JSON file under observer/checks/, or checks.json in the config directory). It
names what an app shows, an independent way to get the same fact, and how to compare them. A
round, started by the owner and never on a schedule, runs every check with the read-only lab_observer account, keeps each reading as a step of
one run, and marks the coverage case each check stands for. A reading that cannot be taken makes
the check unverified, never passed.

    {"id": "spoke-bravo-dataset-count", "title": "...", "ticket": 15,
     "app": "federation_pulse_spoke", "item": "section:pulse_spoke_status:Dataset inventory", "case": "normal",
     "shown":    {"what": "...", "search": {"component": "p-bravo", "app": "federation_pulse_spoke", "query": "..."}, "field": "dataset_count"},
     "expected": {"what": "...", "search": {"component": "p-bravo", "query": "..."}, "field": "value"},
     "compare": "equal"}

A reading is one of:
  search     one search as lab_observer; "component" or "components" (one value each); "field" is
             taken from the first result row. With "each": [names], the search runs once per name on
             the one component, with {each} in the query replaced by the name (one value each).
             "fields": [names] instead of "field" takes several values from the one first row
  page       what a Splunk Web page shows to lab_observer in a headless browser: "component", "path"
             (with any form.* filter values) and "find", a list of regular expressions whose first
             group is taken from the page's visible text once the page has settled (one value each)
  installed  the version and build of an installed app on every component that has it
  image      the version tag of each named component's container image
  value      a fixed value an app rule requires
compare is "equal" (every shown value equals the expected one), "each_equal" (the shown and
expected values are equal one by one, in order) or "all_equal" (every shown value is the same; no
expected reading).

A file may also be {"fragments": {name: text}, "checks": [...]}; {{name}} in a search query is
replaced by the fragment, so checks that share a long calculation state it once.
"""

import json
import re
import threading
import time
import urllib.error
from pathlib import Path

from observer.assistant import Run
from observer.store import utc_now

PACKAGED = Path(__file__).with_name("checks")
# Checks only read. The account cannot write either; this refuses the attempt outright.
CHANGING_COMMAND = re.compile(r"(?i)\|\s*(outputlookup|outputcsv|collect|mcollect|meventcollect|delete|sendemail|sendalert|"
                              r"script|run|runshellscript|dbxoutput|tscollect|summaryindex|sichart|sitimechart|sistats|map)\b")
COMPARES = {"equal", "each_equal", "all_equal"}
CASES = {"normal", "empty", "incorrect", "permission", "error", "recovery"}


class Unreadable(Exception):
    """A reading could not be taken; the check is unverified."""


def load_definitions(config_dir=None):
    """Every valid check, and a list of problems with the files that hold them."""
    files = sorted(PACKAGED.glob("*.json"))
    if config_dir and (Path(config_dir) / "checks.json").exists():
        files.append(Path(config_dir) / "checks.json")
    checks, problems, seen = [], [], set()
    for path in files:
        try:
            items = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            problems.append(f"{path.name}: {error}")
            continue
        fragments = items.get("fragments", {}) if isinstance(items, dict) else {}
        items = items.get("checks", []) if isinstance(items, dict) else items
        for item in items if isinstance(items, list) else []:
            item = _with_fragments(item, fragments)
            problem = _problem(item, seen)
            if problem:
                problems.append(f"{path.name}: {item.get('id', '?') if isinstance(item, dict) else '?'}: {problem}")
                continue
            seen.add(item["id"])
            checks.append(item | {"file": path.name})
    return checks, problems


def _with_fragments(item, fragments):
    """The check with {{name}} in its search queries replaced by the file's fragments."""
    if not isinstance(item, dict) or not isinstance(fragments, dict):
        return item
    item = dict(item)
    for side in ("shown", "expected"):
        reading = item.get(side)
        if isinstance(reading, dict) and isinstance(reading.get("search"), dict) and isinstance(reading["search"].get("query"), str):
            query = re.sub(r"\{\{([a-z0-9_]+)\}\}", lambda match: str(fragments.get(match.group(1), match.group(0))), reading["search"]["query"])
            item[side] = reading | {"search": reading["search"] | {"query": query}}
    return item


def _problem(item, seen):
    if not isinstance(item, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,60}", str(item.get("id", ""))):
        return "needs an id of lowercase letters, digits and dashes"
    if item["id"] in seen:
        return "duplicate id"
    if not item.get("title") or item.get("compare", "equal") not in COMPARES:
        return f"needs a title and compare of one of {sorted(COMPARES)}"
    if item.get("case", "normal") not in CASES:
        return f"case must be one of {sorted(CASES)}"
    readings = [item.get("shown")] + ([item.get("expected")] if item.get("compare", "equal") != "all_equal" else [])
    for reading in readings:
        if not isinstance(reading, dict) or sum(key in reading for key in ("search", "page", "installed", "image", "value")) != 1:
            return "each reading needs exactly one of search, page, installed, image or value"
        page = reading.get("page")
        if page is not None:
            if (not isinstance(page, dict) or not re.fullmatch(r"[A-Za-z0-9._-]+", str(page.get("component", "")))
                    or not str(page.get("path", "")).startswith("/en-US/") or ".." in page["path"]):
                return "a page needs a component and a path that starts with /en-US/"
            find = page.get("find")
            if not isinstance(find, list) or not find or not all(isinstance(text, str) and _compiles(text) for text in find):
                return "a page needs find: a list of regular expressions"
        search = reading.get("search")
        if search is not None:
            if not isinstance(search, dict) or not search.get("query") or not (search.get("component") or search.get("components")):
                return "a search needs a query and a component"
            if CHANGING_COMMAND.search(search["query"]):
                return "a check may only read: the search uses a command that writes or runs something"
            if "{{" in search["query"]:
                return "the search names a fragment its file does not define"
            fields = reading.get("fields")
            if not reading.get("field") and not (isinstance(fields, list) and fields and all(isinstance(name, str) for name in fields)):
                return "a search reading needs the field (or fields) to take"
            if fields and (search.get("each") or search.get("components")):
                return "fields takes several values from one search on one component"
            each = search.get("each")
            if each is not None and (not isinstance(each, list) or not each or "{each}" not in search["query"] or search.get("components")
                                     or not all(re.fullmatch(r"[A-Za-z0-9._-]+", str(name)) for name in each)):
                return "each needs a list of plain names, {each} in the query, and one component"
    return None


def _compiles(expression):
    try:
        re.compile(expression)
        return True
    except re.error:
        return False


def _same(left, right):
    try:
        return float(left) == float(right)
    except (TypeError, ValueError):
        return str(left).strip() == str(right).strip()


class Checks:
    def __init__(self, lab, store, coverage=None, config_dir=None, lab_state=None, read_pages=None):
        self.lab = lab
        self.store = store
        self.coverage = coverage
        self.config_dir = config_dir
        self.lab_state = lab_state  # callable: versions and state of every component, kept with the run
        self.read_pages = read_pages  # callable: what each of a list of pages shows (see Capture.read_pages)
        self.pages = {}  # (check id, side) -> this round's page reading
        self.lock = threading.Lock()
        self.status = {"running": False, "started_at": None, "finished_at": None}

    # --- readings -------------------------------------------------------------------

    def _read(self, run, check, side):
        """Take one reading as a step of the run; returns (values, step number). Values is a list."""
        reading = check[side]
        label = f"{side}: {reading.get('what') or check['title']}"
        if "value" in reading:
            item = run.event("tool", name="check reading", input={"check": check["id"], "reading": label, "rule": reading["value"]},
                             source="app rule in the check definition", status="ok", result=json.dumps(reading["value"]))
            return [reading["value"]], item["seq"]
        if "page" in reading:
            page = reading["page"]
            got = self.pages.get((check["id"], side)) or {"error": "no page reader is available"}
            failure = got.get("error")
            item = run.event("tool", name="check reading",
                             input={"check": check["id"], "reading": label, "component": page["component"], "page": page["path"], "find": page["find"]},
                             source=f"headless Chromium as {getattr(self.lab.source, 'username', 'lab_observer')} via router /lab/{page['component']}/",
                             status="error" if failure else "ok",
                             result=json.dumps({key: got[key] for key in ("values", "url", "read_at", "error", "text") if got.get(key)}, indent=1))
            if failure:
                raise Unreadable(f"{page['component']}{page['path']}: {failure}")
            return got["values"], item["seq"]
        if "installed" in reading:
            app = reading["installed"]
            values = {}
            for component in self.lab.snapshot()["components"]:
                apps = (component["facts"].get("installed_apps") or {}).get("value") or []
                for found in apps:
                    if found["app"] == app:
                        values[component["id"]] = f"{found.get('version') or '?'} build {found.get('build') or '?'}"
            item = run.event("tool", name="check reading", input={"check": check["id"], "reading": label, "installed_app": app},
                             source="lab discovery (splunkd apps/local as lab_observer)", status="ok" if values else "error",
                             result=json.dumps(values, indent=1) if values else f"{app} is not installed on any discovered component")
            if not values:
                raise Unreadable(f"{app} is not installed anywhere")
            return list(values.values()), item["seq"]
        if "image" in reading:
            images = {item["name"]: item.get("image", "") for item in self.lab.source.containers()}
            values = {name: images[name].rpartition(":")[2] for name in reading["image"] if ":" in images.get(name, "")}
            missing = [name for name in reading["image"] if name not in values]
            item = run.event("tool", name="check reading", input={"check": check["id"], "reading": label, "image_of": reading["image"]},
                             source="podman: the image each container was started from", status="error" if missing else "ok",
                             result=json.dumps(values, indent=1))
            if missing:
                raise Unreadable(f"no container image found for {', '.join(missing)}")
            return [values[name] for name in reading["image"]], item["seq"]
        search = reading["search"]
        names = search.get("each")
        components = [search["component"]] * len(names) if names else search.get("components") or [search["component"]]
        values, results, sources, failure = [], {}, [], None
        for index, component in enumerate(components):
            query = search["query"].replace("{each}", names[index]) if names else search["query"]
            key = names[index] if names else component
            try:
                rows, source = self.lab.source.splunk_search(component, query, search.get("earliest", "-24h"),
                                                             search.get("latest", "now"), 5, app=search.get("app"))
                sources.append(source)
                wanted = reading.get("fields") or [reading["field"]]
                missing = [name for name in wanted if not rows or name not in rows[0]]
                if missing:
                    failure = f"{key}: the search returned no {missing[0]!r}"
                    results[key] = rows[:1]
                    continue
                values += [rows[0][name] for name in wanted]
                results[key] = {name: rows[0][name] for name in wanted}
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="replace")
                try:
                    detail = "; ".join(message.get("text", "") for message in json.loads(detail).get("messages", [])) or detail
                except ValueError:
                    pass
                failure = f"{key}: HTTP {error.code}: {detail[:240]}"
                results[key] = failure
            except (OSError, ValueError) as error:
                failure = f"{key}: {error.__class__.__name__}: {str(error)[:200]}"
                results[key] = failure
        item = run.event("tool", name="check reading",
                         input={"check": check["id"], "reading": label, "search": search["query"], "app": search.get("app"),
                                "components": sorted(set(components)), "each": names, "field": reading.get("fields") or reading["field"]},
                         source="; ".join(sorted(set(sources))) or f"splunkd search as {getattr(self.lab.source, 'username', 'lab_observer')}",
                         status="error" if failure else "ok", result=json.dumps(results, indent=1))
        if failure:
            raise Unreadable(failure)
        return values, item["seq"]

    def _judge(self, run, check):
        """Returns (result, detail, step numbers). result is pass, fail or unverified."""
        steps = []
        try:
            shown, step = self._read(run, check, "shown")
            steps.append(step)
            if check.get("compare", "equal") == "all_equal":
                agree = all(_same(value, shown[0]) for value in shown)
                return ("pass" if agree else "fail"), f"shown {', '.join(map(str, shown))}", steps
            expected, step = self._read(run, check, "expected")
            steps.append(step)
        except Unreadable as error:
            return "unverified", str(error), steps
        if check.get("compare") == "each_equal":
            agree = len(shown) == len(expected) and all(_same(left, right) for left, right in zip(shown, expected))
        else:
            agree = all(_same(value, expected[0]) for value in shown) and all(_same(value, expected[0]) for value in expected)
        return ("pass" if agree else "fail"), f"shown {', '.join(map(str, shown))}; expected {', '.join(map(str, expected))}", steps

    # --- a round ----------------------------------------------------------------------

    def summary(self):
        checks, problems = load_definitions(self.config_dir)
        last = self.store.get_setting("check_results", {})
        accepted = self.store.get_setting("check_accepted", {})
        known = lambda check: accepted.get(check["id"]) if self._known(last.get(check["id"]), accepted.get(check["id"])) else None  # noqa: E731
        return {"checks": [check | {"last": last.get(check["id"]), "accepted": known(check)} for check in checks], "problems": problems,
                "status": dict(self.status), "account": getattr(self.lab.source, "username", "lab_observer")}

    @staticmethod
    def _known(last, acceptance):
        """An accepted failure stays accepted only while the check fails with the same finding."""
        return bool(last and acceptance and last["result"] == "fail" and last["detail"] == acceptance["detail"])

    def accept(self, check_id, reason):
        """The owner knows about this failure and why it stays; it stops counting as a new problem.
        Returns False unless the check is failing now."""
        last = self.store.get_setting("check_results", {}).get(check_id)
        reason = str(reason or "").strip()[:300]
        if not last or last["result"] != "fail" or not reason:
            return False
        accepted = self.store.get_setting("check_accepted", {})
        accepted[check_id] = {"detail": last["detail"], "reason": reason, "at": utc_now()}
        self.store.put_setting("check_accepted", accepted)
        return True

    def unaccept(self, check_id):
        accepted = self.store.get_setting("check_accepted", {})
        if accepted.pop(check_id, None) is None:
            return False
        self.store.put_setting("check_accepted", accepted)
        return True

    def run_round(self, ids=None, reason="asked for by the owner"):
        """Run every check (or the named ones) as one run. Returns the run id, or None if a round is already running."""
        if not self.lock.acquire(blocking=False):
            return None
        try:
            self.status.update(running=True, started_at=utc_now())
            checks, problems = load_definitions(self.config_dir)
            if ids:
                checks = [check for check in checks if check["id"] in set(ids)]
            title = f"Checks ({reason}): {len(checks)} read-only comparison(s)"
            run = Run(self.store, title)
            run.record.update(origin="check", model="no AI model: checks defined as data",
                              accounts=[getattr(self.lab.source, "username", "lab_observer")])
            if self.lab_state:
                run.record["lab_state"] = self.lab_state()
            run.event("prompt", text=title)
            for problem in problems:
                run.event("error", text=f"Check definition skipped: {problem}")
            self._open_pages(run, checks)
            results = self.store.get_setting("check_results", {})
            counts = {"pass": 0, "fail": 0, "unverified": 0}
            accepted = self.store.get_setting("check_accepted", {})
            known = 0
            evidence = []
            for check in checks:
                result, detail, steps = self._judge(run, check)
                counts[result] += 1
                evidence += steps
                acceptance = accepted.get(check["id"])
                if acceptance and not self._known({"result": result, "detail": detail}, acceptance):
                    # It passes again, or fails differently: the owner accepted something else.
                    del accepted[check["id"]]
                    acceptance = None
                known += bool(acceptance)
                outcome = run.event("check", check=check["id"], title=check["title"], result=result, detail=detail,
                                    evidence_steps=steps, ticket=check.get("ticket"),
                                    accepted=acceptance["reason"] if acceptance else None)
                before = results.get(check["id"]) or {}
                changed = before.get("result") != result
                # "since" is when the check first gave this result; "was" is what it gave before that.
                results[check["id"]] = {"result": result, "detail": detail, "at": outcome["at"], "run_id": run.id,
                                        "steps": steps, "step": outcome["seq"],
                                        "since": outcome["at"] if changed else before.get("since") or before.get("at") or outcome["at"],
                                        "was": before.get("result") if changed else before.get("was")}
            self.store.put_setting("check_results", results)
            self.store.put_setting("check_accepted", accepted)
            self._mark_all(run, checks, results)
            verdict = "fail" if counts["fail"] > known else "inconclusive" if counts["unverified"] or known or not checks else "pass"
            run.record["verdict"] = {"verdict": verdict, "evidence_steps": evidence, "recorded_at": utc_now(),
                                     "summary": f"{counts['pass']} passed, {counts['fail']} failed, {counts['unverified']} could not be verified."
                                                + (f" {known} of the failures {'is' if known == 1 else 'are'} known and accepted by the owner." if known else "")}
            run.event("verdict", **run.record["verdict"])
            run.set_status("done")
            return run.id
        finally:
            self.status.update(running=False, finished_at=utc_now())
            self.lock.release()

    def _open_pages(self, run, checks):
        """Read every page this round needs with one browser, before the comparisons."""
        wanted = [(check["id"], side, check[side]["page"]) for check in checks for side in ("shown", "expected")
                  if isinstance(check.get(side), dict) and "page" in check[side]]
        self.pages = {}
        if not wanted or not self.read_pages:
            return
        started = time.time() - 5
        try:
            read = self.read_pages([{"key": f"{check_id}|{side}", "component": page["component"], "path": page["path"], "find": page["find"]}
                                    for check_id, side, page in wanted])
        except Exception as error:  # the browser could not run; each page check says so and stays unverified
            run.event("error", text=f"The page reader failed: {error.__class__.__name__}: {str(error)[:300]}")
            read = {}
        # Each page left its dashboard's search jobs behind; remove them so they do not use up the
        # read-only account's search disk quota before the comparisons and the next round.
        forget = getattr(self.lab.source, "forget_searches", None)
        for component in sorted({page["component"] for _id, _side, page in wanted}) if forget else []:
            try:
                gone = forget(component, started)
                run.event("text", text=f"Removed {gone} search job(s) the page reader left on {component}.")
            except Exception as error:
                run.event("error", text=f"Could not remove the page reader's search jobs on {component}: {error.__class__.__name__}: {str(error)[:200]}")
        for check_id, side, _page in wanted:
            self.pages[(check_id, side)] = read.get(f"{check_id}|{side}") or {"error": "the page reader gave no reading"}

    def _mark_all(self, run, ran, results):
        """One coverage mark per item and case the round touched. Several checks can stand for the same
        case, so the mark is the worst of their latest results: a failure is never hidden by a pass."""
        every, _problems = load_definitions(self.config_dir)
        key = lambda check: (check.get("app"), check.get("item"), check.get("case", "normal"))  # noqa: E731
        rank = {"fail": 0, "unverified": 1, "pass": 2}
        for case in dict.fromkeys(key(check) for check in ran if check.get("app") and check.get("item")):
            group = [check for check in every if key(check) == case and check["id"] in results]
            worst = min(group, key=lambda check: rank[results[check["id"]]["result"]])
            last = results[worst["id"]]
            steps = [step for check in group if results[check["id"]]["run_id"] == run.id for step in results[check["id"]]["steps"]]
            others = len(group) - 1
            detail = last["detail"] + (f" ({others} other check(s) on this case)" if others else "")
            self._mark(run, worst, last["result"], detail, steps or last["steps"])

    def _mark(self, run, check, result, detail, steps):
        """Mark the coverage case the check stands for, when it names an item of a configured app."""
        if not self.coverage or not check.get("app") or not check.get("item"):
            return
        source = self.coverage.source_for(check["app"])
        try:
            known = source and check["item"] in {item["id"] for item in self.coverage.app_map(source)["items"]}
        except Exception:  # the app's source is unreadable; the check result itself is still recorded
            known = False
        if not known:
            run.event("text", text=f"No coverage mark for {check['id']}: {check['item']} is not an item of {check['app']} at the installed version.")
            return
        tested = result in {"pass", "fail"}
        stored = self.coverage.record(source["app"], check["item"], check.get("case", "normal"), "tested" if tested else "unverified",
                                      verdict=result if tested else None, run_id=run.id, evidence=steps,
                                      note=f"check {check['id']}: {detail}"[:500], by="check")
        run.event("coverage", app=source["app"], item=check["item"], case=check.get("case", "normal"),
                  result=result if stored == "tested" else stored, evidence_steps=steps, note=f"check {check['id']}")
