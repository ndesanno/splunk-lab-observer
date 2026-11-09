"""Read-only access to the lab: container metadata, Splunk REST, and component discovery.

Every discovered value is a fact that carries the source it came from and when it was checked.
Owner-edited names and descriptions are kept apart from discovered facts.
"""

import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ElementTree
import ssl
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from observer.store import utc_now


DEFAULT_SPLUNK_CONFIG = Path.home() / ".config" / "splunk-lab-observer" / "splunk.json"
APP_PROBE = Path(__file__).with_name("app_probe.py")
# Splunk Web pages that exist on every instance, plus pages that exist only for a role.
BUILTIN_SCREENS = [
    ("Settings", "Indexes", "/en-US/manager/search/data/indexes", None),
    ("Settings", "Apps", "/en-US/manager/launcher/apps/local", None),
    ("Settings", "Users", "/en-US/manager/launcher/authentication/users", None),
    ("Settings", "Server settings", "/en-US/manager/launcher/server/settings", None),
    ("Settings", "Indexer clustering", "/en-US/manager/system/clustering", {"cluster_manager", "cluster_peer", "cluster_search_head"}),
    ("Settings", "Forwarding and receiving", "/en-US/manager/launcher/forwardreceive", None),
]
LAB_NETWORK = "pulseprod"


def fact(value, source, checked_at):
    return {"value": value, "source": source, "checked_at": checked_at}


def classify(image, name):
    image = image.lower()
    if "splunk/splunk" in image:
        return "splunk_enterprise"
    if "universalforwarder" in image:
        return "universal_forwarder"
    if "haproxy" in image:
        return "observer_router" if name == "p-observer-router" else "load_balancer"
    if "alpine" in image:
        return "data_generator"
    return "container"


class PodmanSplunkSource:
    """The real lab: podman on this host and splunkd behind the observer router."""

    def __init__(self, splunk_config=DEFAULT_SPLUNK_CONFIG, network=LAB_NETWORK):
        path = Path(splunk_config)
        if path.stat().st_mode & 0o077:
            raise ValueError("The Splunk observer credential file must be private to its owner")
        config = json.loads(path.read_text(encoding="utf-8"))
        self.username = config["username"]
        self._authorization = "Basic " + base64.b64encode(f"{config['username']}:{config['password']}".encode()).decode()
        self.router = config.get("router", "http://127.0.0.1:8190").rstrip("/")
        self.network = network

    def password_for_capture(self):
        """Only the preview capture needs the password itself, to sign in to Splunk Web."""
        return base64.b64decode(self._authorization.split(" ", 1)[1]).decode().split(":", 1)[1]

    def containers(self):
        result = subprocess.run(["podman", "ps", "-a", "--format", "json"], capture_output=True, text=True, timeout=30, check=True)
        containers = []
        for item in json.loads(result.stdout or "[]"):
            if self.network not in (item.get("Networks") or []):
                continue
            status = item.get("Status", "")
            health = next((word for word in ("unhealthy", "healthy", "starting") if f"({word})" in status), None)
            containers.append({
                "name": item["Names"][0],
                "image": item.get("Image", ""),
                "state": item.get("State", "unknown"),
                "status": status,
                "health": health,
                "started_at": item.get("StartedAt"),
                "ports": [f"{port.get('host_ip') or '0.0.0.0'}:{port['host_port']}->{port['container_port']}"
                          for port in (item.get("Ports") or [])],
            })
        return containers

    def splunk_get(self, component, path, **params):
        params.setdefault("output_mode", "json")
        params.setdefault("count", "0")
        source = f"splunkd {component}{path}"
        url = f"{self.router}/mgmt/{component}{path}?{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(url, headers={"Authorization": self._authorization})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response), source

    def splunk_search(self, component, query, earliest, latest, max_count):
        """A blocking one-shot search as the read-only account; returns result rows."""
        source = f"splunkd {component}/services/search/jobs (oneshot) as {self.username}"
        body = urllib.parse.urlencode({"search": query, "exec_mode": "oneshot", "earliest_time": earliest,
                                       "latest_time": latest, "count": max_count, "output_mode": "json"}).encode()
        request = urllib.request.Request(f"{self.router}/mgmt/{component}/services/search/jobs", data=body,
                                         headers={"Authorization": self._authorization})
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.load(response).get("results", []), source

    def container_action(self, component, action):
        """Start, stop, or restart one lab container. Only an owner-approved assistant step calls this."""
        if action not in {"start", "stop", "restart"}:
            raise ValueError(action)
        result = subprocess.run(["podman", action, component], capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip()[:300] or f"exit {result.returncode}")

    def web_status(self, component):
        try:
            with urllib.request.urlopen(f"{self.router}/lab/{component}/en-US/account/login", timeout=8) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except OSError:
            return None

    def read_command(self, component, argv, user=None):
        """A fixed, read-only command inside a container (config reads, logs)."""
        result = subprocess.run(["podman", "exec", *(["-u", user] if user else []), component, *argv],
                                capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip()[:200] or f"exit {result.returncode}")
        return result.stdout

    def logs(self, component, tail=80):
        result = subprocess.run(["podman", "logs", "--tail", str(tail), component], capture_output=True, text=True, timeout=20)
        return (result.stdout + result.stderr)[-20000:]

    def stats(self):
        result = subprocess.run(["podman", "stats", "--no-stream", "--format", "json"], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {}
        return {item.get("name") or item.get("Name"): item for item in json.loads(result.stdout or "[]")}


class OperatorAccount:
    """The lab_operator account (admin role), used only for splunkd changes the owner approves."""

    def __init__(self, config_file):
        path = Path(config_file)
        if path.stat().st_mode & 0o077:
            raise ValueError("The Splunk operator credential file must be private to its owner")
        config = json.loads(path.read_text(encoding="utf-8"))
        self.username = config["username"]
        self._authorization = "Basic " + base64.b64encode(f"{config['username']}:{config['password']}".encode()).decode()
        self.router = config.get("router", "http://127.0.0.1:8190").rstrip("/")

    def request(self, component, method, path, params):
        """POST or DELETE one splunkd endpoint; returns the HTTP status and the JSON reply."""
        query = urllib.parse.urlencode({"output_mode": "json"})
        data = urllib.parse.urlencode(params).encode() if method == "POST" else None
        request = urllib.request.Request(f"{self.router}/mgmt/{component}{path}?{query}", data=data, method=method,
                                         headers={"Authorization": self._authorization})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            body = error.read()
            try:
                reply = json.loads(body or b"{}")
            except ValueError:
                reply = {"text": body.decode("utf-8", errors="replace")[:500]}
            return error.code, reply


def screens_from_nav(app):
    """Screens in an app's navigation menu, in menu order, with view labels from the view files."""
    base = f"/en-US/app/{app['app']}/"
    screens, seen = [], set()

    def add(label, path, group):
        if path in seen:
            return
        seen.add(path)
        screens.append({"app": app["app"], "app_label": app["label"] or app["app"], "app_version": app["version"],
                        "group": group, "label": label, "path": path, "source": f"{app['app']} navigation menu"})

    def walk(node, group):
        for child in node:
            if child.tag == "view" and child.get("name"):
                name = child.get("name")
                add(app["views"].get(name) or name.replace("_", " ").capitalize(), base + name, group)
            elif child.tag == "a" and child.get("href"):
                href = child.get("href").strip()
                if href.startswith(("http:", "https:", "//")):
                    continue
                path = href if href.startswith("/en-US/") else ("/en-US" + href if href.startswith("/") else base + href)
                add((child.text or href).strip(), path, group)
            elif child.tag == "collection":
                walk(child, child.get("label") or group)

    try:
        root = ElementTree.fromstring(app["nav"]) if app.get("nav") else None
    except ElementTree.ParseError:
        root = None
    if root is not None:
        walk(root, None)
    if not screens:
        add(app["label"] or app["app"], base, None)
    return screens


def entries(payload):
    return [entry for entry in payload.get("entry", [])]


class Lab:
    """The component registry: discovery results plus owner labels."""

    def __init__(self, source, store):
        self.source = source
        self.store = store
        self.lock = threading.Lock()
        self.registry = {"components": [], "groups": [], "relationships": [], "checked_at": None, "errors": []}

    # --- discovery -----------------------------------------------------------------

    def discover(self):
        checked_at = utc_now()
        errors = []
        components = {}
        for container in self.source.containers():
            name = container["name"]
            kind = classify(container["image"], name)
            source = "podman ps"
            components[name] = {
                "id": name,
                "kind": kind,
                # Every Splunk Enterprise instance serves Splunk Web under /lab/<name>/ (see the lab's observer.sh).
                "web_path": f"/lab/{name}/" if kind == "splunk_enterprise" else None,
                "screens": [],
                "facts": {
                    "kind": fact(kind, f"{source} (image {container['image']})", checked_at),
                    "image": fact(container["image"], source, checked_at),
                    "container_state": fact(container["state"], source, checked_at),
                    "container_health": fact(container["health"], source, checked_at),
                    "published_ports": fact(container["ports"], source, checked_at),
                },
            }
        groups, relationships = [], []
        splunk = [name for name, component in components.items() if component["kind"] == "splunk_enterprise"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = dict(zip(splunk, pool.map(self._discover_splunk, splunk)))
        running_splunk = [name for name in splunk if components[name]["facts"]["container_state"]["value"] == "running"]
        with ThreadPoolExecutor(max_workers=6) as pool:
            app_results = dict(zip(running_splunk, pool.map(self._discover_apps, running_splunk)))
        for name, (facts, found_groups, found_relationships, problems) in results.items():
            components[name]["facts"].update(facts)
            apps, screens, app_source, app_error = app_results.get(name, (None, [], None, None))
            if apps is not None:
                components[name]["facts"]["installed_apps"] = fact(
                    [{key: app[key] for key in ("app", "label", "version", "build", "visible", "disabled")} for app in apps],
                    app_source, checked_at)
                components[name]["screens"] = screens + self._builtin_screens(facts)
            elif app_error:
                errors.append({"component": name, "source": app_source, "error": app_error})
            groups.extend(found_groups)
            relationships.extend(found_relationships)
            errors.extend(problems)
        for name, component in components.items():
            if component["kind"] == "load_balancer" and component["facts"]["container_state"]["value"] == "running":
                relationships.extend(self._discover_load_balancer(name, checked_at, errors))
            running = component["facts"]["container_state"]["value"] == "running"
            if component["kind"] == "universal_forwarder" and running:
                relationships.extend(self._discover_forwarder(name, "/opt/splunkforwarder", checked_at, errors))
            if "heavyweight_forwarder" in (component["facts"].get("server_roles") or {}).get("value", []) and running:
                relationships.extend(self._discover_forwarder(name, "/opt/splunk", checked_at, errors))
        groups = self._merge_groups(groups)
        relationships = [item for item in relationships if item["to"] in components and item["from"] in components]
        with self.lock:
            self.registry = {
                "components": sorted(components.values(), key=lambda item: item["id"]),
                "groups": groups,
                "relationships": relationships,
                "checked_at": checked_at,
                "errors": errors,
            }
        return self.registry

    def _get(self, name, path, problems, **params):
        try:
            return self.source.splunk_get(name, path, **params)
        except urllib.error.HTTPError as error:
            problems.append({"component": name, "source": f"splunkd {name}{path}", "error": f"HTTP {error.code}"})
        except (OSError, ValueError) as error:
            problems.append({"component": name, "source": f"splunkd {name}{path}", "error": error.__class__.__name__})
        return None, None

    def _discover_splunk(self, name):
        checked_at = utc_now()
        facts, groups, relationships, problems = {}, [], [], []
        info, source = self._get(name, "/services/server/info", problems)
        if not info:
            return facts, groups, relationships, problems
        content = entries(info)[0]["content"]
        facts["splunk_version"] = fact(content.get("version"), source, checked_at)
        facts["server_name"] = fact(content.get("serverName"), source, checked_at)
        facts["server_roles"] = fact(content.get("server_roles", []), source, checked_at)
        roles = set(content.get("server_roles", []))

        if roles & {"cluster_manager", "cluster_master"}:
            config, config_source = self._get(name, "/services/cluster/config", problems)
            label = entries(config)[0]["content"].get("cluster_label") if config else None
            peers, peers_source = self._get(name, "/services/cluster/manager/peers", problems)
            members = [entry["content"].get("label") for entry in entries(peers)] if peers else []
            group_id = f"indexer-cluster:{name}"
            groups.append({"id": group_id, "type": "indexer_cluster", "label": label, "manager": name,
                           "members": [name, *members], "source": peers_source or config_source, "checked_at": checked_at})
            for member in members:
                status = next(entry["content"].get("status") for entry in entries(peers) if entry["content"].get("label") == member)
                relationships.append({"from": name, "to": member, "type": "manages indexer peer",
                                      "detail": status, "source": peers_source, "checked_at": checked_at})
        if "shc_member" in roles or "shc_captain" in roles:
            status, status_source = self._get(name, "/services/shcluster/status", problems)
            if status:
                body = entries(status)[0]["content"]
                captain = body.get("captain", {}).get("label")
                members = sorted(peer.get("label") for peer in body.get("peers", {}).values())
                config, _ = self._get(name, "/services/shcluster/config", problems)
                label = entries(config)[0]["content"].get("shcluster_label") if config else None
                facts["shc_captain"] = fact(captain, status_source, checked_at)
                groups.append({"id": f"search-head-cluster:{label or captain}", "type": "search_head_cluster",
                               "label": label, "captain": captain, "members": members,
                               "source": status_source, "checked_at": checked_at})
        if "shc_deployer" in roles or "deployer" in roles:
            facts["deployer"] = fact(True, source, checked_at)
        providers, providers_source = self._get(name, "/services/data/federated/provider", [])
        for entry in entries(providers or {}):
            host = (entry["content"].get("hostPort") or "").split(":")[0]
            relationships.append({"from": name, "to": host, "type": "federated search provider",
                                  "detail": entry["name"], "source": providers_source, "checked_at": checked_at})
        return facts, groups, relationships, problems

    def _discover_apps(self, name):
        source = f"podman exec {name} (installed app.conf, navigation, and view files under etc/apps)"
        try:
            text = self.source.read_command(name, ["/opt/splunk/bin/splunk", "cmd", "python3", "-c", APP_PROBE.read_text()],
                                            user="splunk")
            apps = json.loads(text)
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            return None, [], source, str(error)[:200]
        screens = []
        for app in apps:
            if not app["visible"] or app["disabled"]:
                continue
            screens.extend(screens_from_nav(app))
        return apps, screens, source, None

    @staticmethod
    def _builtin_screens(facts):
        roles = set((facts.get("server_roles") or {}).get("value", []))
        return [{"app": "settings", "app_label": group, "app_version": None, "group": None, "label": label, "path": path,
                 "source": "Splunk Web built-in page"}
                for group, label, path, needs in BUILTIN_SCREENS if needs is None or roles & needs]

    def _discover_load_balancer(self, name, checked_at, errors):
        source = f"podman exec {name} cat /usr/local/etc/haproxy/haproxy.cfg"
        try:
            text = self.source.read_command(name, ["cat", "/usr/local/etc/haproxy/haproxy.cfg"])
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            errors.append({"component": name, "source": source, "error": str(error)})
            return []
        backends = re.findall(r"^\s*server\s+\S+\s+([A-Za-z0-9_.-]+):(\d+)", text, re.M)
        return [{"from": name, "to": host, "type": "load balances", "detail": f"port {port}", "source": source,
                 "checked_at": checked_at} for host, port in backends]

    def _discover_forwarder(self, name, home, checked_at, errors):
        argv = [f"{home}/bin/splunk", "btool", "outputs", "list", "--no-log"]
        source = f"podman exec {name} splunk btool outputs list"
        try:
            # The image's default exec user cannot read the forwarder's configuration.
            text = self.source.read_command(name, argv, user="splunk")
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            errors.append({"component": name, "source": source, "error": str(error)})
            return []
        targets = []
        for line in text.splitlines():
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key == "server":
                targets += [(item.strip().split(":")[0], "sends data to") for item in value.split(",") if item.strip()]
            elif key in {"manager_uri", "master_uri"}:
                host = urllib.parse.urlsplit(value).hostname
                if host:
                    targets.append((host, "discovers indexers through"))
        return [{"from": name, "to": host, "type": kind, "source": source, "checked_at": checked_at}
                for host, kind in dict.fromkeys(targets)]

    @staticmethod
    def _merge_groups(groups):
        merged = {}
        for group in groups:
            existing = merged.get(group["id"])
            if existing:
                existing["members"] = sorted(set(existing["members"]) | set(group["members"]))
            else:
                merged[group["id"]] = dict(group, members=sorted(set(group["members"])))
        return sorted(merged.values(), key=lambda item: item["id"])

    # --- registry with owner labels -------------------------------------------------

    def snapshot(self):
        labels = self.store.get_setting("labels", {})
        with self.lock:
            registry = json.loads(json.dumps(self.registry))
        for component in registry["components"]:
            owner = labels.get(component["id"], {})
            component["owner_name"] = owner.get("name")
            component["owner_description"] = owner.get("description")
            component["owner_edited_at"] = owner.get("edited_at")
        return registry

    def component(self, component_id):
        return next((item for item in self.snapshot()["components"] if item["id"] == component_id), None)

    def web_components(self):
        with self.lock:
            return {item["id"] for item in self.registry["components"] if item["web_path"]}

    def set_label(self, component_id, name, description):
        if component_id not in {item["id"] for item in self.registry["components"]}:
            raise KeyError(component_id)
        labels = self.store.get_setting("labels", {})
        name = (name or "").strip()[:80]
        description = (description or "").strip()[:500]
        if name or description:
            labels[component_id] = {"name": name or None, "description": description or None, "edited_at": utc_now()}
        else:
            labels.pop(component_id, None)
        self.store.put_setting("labels", labels)
