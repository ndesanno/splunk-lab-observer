"""Which features and screens of each app have been tested, and in which cases.

The inventory comes from each app's source, read with git at the ref that matches the installed
version (a tag such as v0.8.1 or v0.10.6-build.100641) or, failing that, the default branch: screens
and their panels or page sections, actions, saved searches, search commands, REST handlers, inputs,
and KV store collections, each with the file and line it comes from. Coverage marks link an item and
case to the run and steps that support them; "tested" needs a pass or fail verdict with evidence.

Sources are listed in coverage-sources.json in the observer's config directory:

    [{"app": "TA-my_addon", "repo": "~/src/my-addon", "path": "TA-my_addon"},
     {"app": "my_app", "repo": "~/src/my-app", "path": "apps/my_app", "ui": {"ui/src/pages": "my_app_overview"}}]

"ui" maps a React source folder to the view it renders into, for pages drawn by JavaScript.
"""

import configparser
import json
import re
import subprocess
import threading
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from observer.store import utc_now

CASES = ["normal", "empty", "incorrect", "permission", "error", "recovery"]
STATUSES = {"tested", "unverified", "untested", "n/a"}
KINDS = ["screen", "panel", "section", "action", "scheduled search", "saved search", "command", "rest endpoint",
         "input", "kv collection"]
HEADING = re.compile(r"<Heading\b[^>]*>\s*([^<{}][^<{}]*?)\s*</Heading>")
BUTTON = re.compile(r"<Button\b[^>]*?\blabel=\"([^\"]+)\"")


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip()[:200] or f"git {args[0]} failed")
    return result.stdout


def line_of(text, needle):
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else None


def parse_conf(text):
    """Stanzas of a .conf file with each stanza's line number."""
    stanzas, current = {}, None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            stanzas[current] = {"_line": number}
        elif current is not None and "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            stanzas[current][key.strip()] = value.strip()
    return stanzas


class Coverage:
    def __init__(self, store, lab, config_dir):
        self.store = store
        self.lab = lab
        self.config_file = Path(config_dir) / "coverage-sources.json"
        self.cache = {}  # (repo, commit, path) -> inventory
        self.lock = threading.Lock()
        with store.lock, store.db:
            store.db.execute("""CREATE TABLE IF NOT EXISTS coverage (
                id INTEGER PRIMARY KEY, app TEXT NOT NULL, item TEXT NOT NULL, kase TEXT NOT NULL, status TEXT NOT NULL,
                verdict TEXT, run_id TEXT, evidence TEXT, note TEXT, by TEXT NOT NULL, at TEXT NOT NULL)""")

    def sources(self):
        if not self.config_file.exists():
            return []
        items = json.loads(self.config_file.read_text(encoding="utf-8"))
        return [dict(item, repo=str(Path(item["repo"]).expanduser())) for item in items]

    # --- versions -----------------------------------------------------------------

    def installed(self, app):
        """Installed version and build of an app on every component that has it."""
        found = []
        for component in self.lab.snapshot()["components"]:
            for item in (component["facts"].get("installed_apps") or {}).get("value", []):
                if item["app"] == app:
                    found.append({"component": component["id"], "version": item["version"], "build": item["build"],
                                  "disabled": item["disabled"]})
        return found

    def resolve(self, source, installed):
        """The git ref to inventory: the tag for the most common installed version, else the default branch."""
        repo = source["repo"]
        tags = set(git(repo, "tag", "--list").split())
        common = {}
        for item in installed:
            key = (item["version"], item["build"])
            common[key] = common.get(key, 0) + 1
        ranked = sorted(common, key=lambda key: -common[key])
        def exact(ref, version, build):
            try:
                found = self.source_version(source, ref)
            except RuntimeError:
                return False
            return found["version"] == version and (found["build"] == build or not build)

        for version, build in ranked:
            for tag in (f"v{version}-build.{build}", f"v{version}", str(version)):
                if tag in tags and exact(tag, version, build):
                    return tag, f"tag with the installed version {version}" + (f" build {build}" if build else "")
        # An untagged build (a release candidate, say) is often still on a local branch.
        branches = git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()[:50]
        for version, build in ranked:
            for branch in branches:
                if build and exact(branch, version, build):
                    return branch, f"local branch with the installed version {version} build {build}"
        for version, build in ranked:
            for tag in (f"v{version}", str(version)):
                if tag in tags:
                    return tag, f"tag for the installed version {version}"
        return git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), "no tag matches the installed version; default branch"

    def source_version(self, source, ref):
        text = git(source["repo"], "show", f"{ref}:{source['path']}/default/app.conf")
        parser = configparser.ConfigParser(strict=False, interpolation=None)
        parser.read_string(text)
        get = lambda section, key: parser.get(section, key, fallback=None)
        return {"ref": ref, "commit": git(source["repo"], "rev-parse", "--short", f"{ref}^{{commit}}").strip(),
                "version": get("launcher", "version") or get("id", "version"), "build": get("install", "build"),
                "label": get("ui", "label")}

    # --- inventory ----------------------------------------------------------------

    def inventory(self, source, ref):
        commit = git(source["repo"], "rev-parse", f"{ref}^{{commit}}").strip()
        key = (source["repo"], commit, source["path"])
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        items = self._inventory(source, ref)
        with self.lock:
            self.cache[key] = items
        return items

    def _inventory(self, source, ref):
        repo, base = source["repo"], source["path"]
        show = lambda path: git(repo, "show", f"{ref}:{path}")
        files = set(git(repo, "ls-tree", "-r", "--name-only", ref, "--", base).split("\n"))
        items = []

        seen = {}

        def add(kind, item_id, label, path, line, parent=None, detail=None):
            where = f"{path}:{line}" if line else path
            if item_id in seen:  # the same heading or button drawn in more than one place
                seen[item_id]["also"].append(where)
                return
            seen[item_id] = {"id": item_id, "kind": kind, "label": label, "source": where, "also": [],
                             "parent": parent, "detail": detail}
            items.append(seen[item_id])

        views_dir = f"{base}/default/data/ui/views/"
        nav_path = f"{base}/default/data/ui/nav/default.xml"
        in_nav = set()
        if nav_path in files:
            try:
                in_nav = {node.get("name") for node in ElementTree.fromstring(show(nav_path)).iter("view")}
            except ElementTree.ParseError:
                pass
        for path in sorted(name for name in files if name.startswith(views_dir) and name.endswith(".xml")):
            view = path[len(views_dir):-4]
            text = show(path)
            match = re.search(r"<label>(.*?)</label>", text, re.S)
            label = match.group(1).strip() if match else view
            add("screen", f"screen:{view}", label, path, line_of(text, "<label>"),
                detail="in the app menu" if view in in_nav else "not in the app menu")
            for title in re.finditer(r"<panel\b[^>]*>\s*<title>(.*?)</title>", text, re.S):
                panel = re.sub(r"\s+", " ", title.group(1)).strip()
                add("panel", f"panel:{view}:{panel[:60]}", panel, path, text.count("\n", 0, title.start()) + 1, f"screen:{view}")
        for folder, view in (source.get("ui") or {}).items():
            ui_files = sorted(name for name in git(repo, "ls-tree", "-r", "--name-only", ref, "--", folder).split("\n")
                              if name.endswith(".tsx") and ".unit." not in name)
            for path in ui_files:
                text = show(path)
                for match in HEADING.finditer(text):
                    add("section", f"section:{view}:{match.group(1)[:60]}", match.group(1), path,
                        text.count("\n", 0, match.start()) + 1, f"screen:{view}")
                for match in BUTTON.finditer(text):
                    add("action", f"action:{view}:{match.group(1)[:60]}", match.group(1), path,
                        text.count("\n", 0, match.start()) + 1, f"screen:{view}")
        conf = lambda name: (f"{base}/default/{name}", parse_conf(show(f"{base}/default/{name}"))) \
            if f"{base}/default/{name}" in files else (None, {})
        path, stanzas = conf("savedsearches.conf")
        for name, values in stanzas.items():
            if name == "default":
                continue
            scheduled = values.get("enableSched", "0").lower() in {"1", "true"} or "cron_schedule" in values
            alerting = any(key.startswith("action.") and values[key].lower() in {"1", "true"} for key in values
                           if key.count(".") == 1)
            add("scheduled search" if scheduled else "saved search", f"search:{name}", name, path, values["_line"],
                detail=", ".join(filter(None, [f"cron {values['cron_schedule']}" if "cron_schedule" in values else "",
                                               "alert action" if alerting else "",
                                               "disabled by default" if values.get("disabled", "0") in {"1", "true"} else ""])) or None)
        for filename, kind in (("commands.conf", "command"), ("restmap.conf", "rest endpoint"),
                               ("inputs.conf", "input"), ("collections.conf", "kv collection")):
            path, stanzas = conf(filename)
            for name, values in stanzas.items():
                if name == "default" or (kind == "input" and "://" not in name and len(stanzas) > 1 and
                                         any(other.startswith(name + "://") for other in stanzas)):
                    continue
                add(kind, f"{kind.split()[0]}:{name}", name, path, values["_line"])
        order = {kind: index for index, kind in enumerate(KINDS)}
        return sorted(items, key=lambda item: (order[item["kind"]], item["source"]))

    # --- marks --------------------------------------------------------------------

    def record(self, app, item, case, status, verdict=None, run_id=None, evidence=None, note=None, by="owner"):
        """Mark one case of one item. Without a verdict and evidence, "tested" is stored as unverified."""
        if case not in CASES or status not in STATUSES:
            raise ValueError(f"case must be one of {CASES} and status one of {sorted(STATUSES)}")
        if status == "tested" and (verdict not in {"pass", "fail"} or not evidence):
            status = "unverified"
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "INSERT INTO coverage (app, item, kase, status, verdict, run_id, evidence, note, by, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (app, item, case, status, verdict if status == "tested" else None, run_id, json.dumps(evidence or []),
                 (note or "")[:500] or None, by, utc_now()))
        return status

    def marks(self, app):
        """Every mark for an app, newest first."""
        with self.store.lock:
            rows = self.store.db.execute("SELECT * FROM coverage WHERE app = ? ORDER BY id DESC", (app,)).fetchall()
        return [{key: row[key] for key in row.keys()} | {"case": row["kase"], "evidence": json.loads(row["evidence"] or "[]")}
                for row in rows]

    # --- the map ------------------------------------------------------------------

    def app_map(self, source):
        installed = self.installed(source["app"])
        ref, why = self.resolve(source, installed)
        version = self.source_version(source, ref)
        head = git(source["repo"], "rev-parse", "--abbrev-ref", "HEAD").strip()
        head_version = self.source_version(source, head) if head != ref else version
        dirty = bool(git(source["repo"], "status", "--porcelain", "--", source["path"]).strip())
        items = [dict(item) for item in self.inventory(source, ref)]
        latest = {}
        for mark in self.marks(source["app"]):
            latest.setdefault((mark["item"], mark["case"]), mark)
        counts = {status: 0 for status in ("pass", "fail", "unverified", "untested", "n/a")}
        for item in items:
            item["cases"] = {}
            for case in CASES:
                mark = latest.get((item["id"], case))
                item["cases"][case] = mark
                key = "untested" if mark is None or mark["status"] == "untested" else \
                      mark["verdict"] if mark["status"] == "tested" else mark["status"]
                counts[key] += 1
        for entry in installed:
            entry["matches_source"] = (entry["version"], entry["build"]) == (version["version"], version["build"])
        builds = sorted({entry["build"] for entry in installed if not entry["matches_source"] and entry["build"]})
        if builds and why.startswith("tag"):
            why += f"; installed build {', '.join(builds)} has no tag of its own, so the source may differ from what runs"
        return {"app": source["app"], "label": version["label"] or source["app"], "repo": source["repo"],
                "path": source["path"], "source": version, "source_reason": why, "default_branch": head_version,
                "working_tree_changes": dirty, "installed": installed, "items": items, "cases": CASES, "counts": counts}

    def full_map(self):
        apps, errors = [], []
        for source in self.sources():
            try:
                apps.append(self.app_map(source))
            except (OSError, RuntimeError, ValueError, configparser.Error) as error:
                errors.append({"app": source.get("app"), "error": f"{error.__class__.__name__}: {error}"[:300]})
        return {"apps": apps, "errors": errors, "checked_at": utc_now(), "config": str(self.config_file)}

    def source_for(self, app):
        return next((item for item in self.sources() if item["app"] == app), None)
