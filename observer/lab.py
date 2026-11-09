"""Read-only access to the lab: container metadata, Splunk REST, and component discovery.

Every discovered value is a fact that carries the source it came from and when it was checked.
Owner-edited names and descriptions are kept apart from discovered facts.
"""

import base64
import json
import re
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
        for name, (facts, found_groups, found_relationships, problems) in results.items():
            components[name]["facts"].update(facts)
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
