"""Lightweight background collection: discovery, health, messages, and resource use.

Each poll stores observations; a status that differs from its last value becomes a
change in the component's history, linked to the observation that showed it.
"""

import threading
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor

from observer.store import utc_now


HEALTH_INTERVAL_SECONDS = 60
DISCOVERY_INTERVAL_SECONDS = 300
PRUNE_INTERVAL_SECONDS = 6 * 60 * 60


class Monitor:
    def __init__(self, lab, store, capture=None):
        self.lab = lab
        self.store = store
        self.capture = capture
        self.stop_event = threading.Event()
        self.thread = None
        self.last = {"discovery": 0.0, "health": 0.0, "prune": 0.0}
        self.status = {"discovery_at": None, "health_at": None, "last_error": None}

    def start(self):
        self.thread = threading.Thread(target=self._loop, name="observer-monitor", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def _loop(self):
        while not self.stop_event.is_set():
            now = time.time()
            try:
                if now - self.last["discovery"] >= DISCOVERY_INTERVAL_SECONDS:
                    self.discover()
                if now - self.last["health"] >= HEALTH_INTERVAL_SECONDS:
                    self.collect()
                if now - self.last["prune"] >= PRUNE_INTERVAL_SECONDS:
                    self.store.prune()
                    if self.capture:
                        self.capture.prune()
                    self.last["prune"] = now
            except Exception as error:  # keep monitoring through one bad poll
                self.status["last_error"] = f"{utc_now()} {error.__class__.__name__}: {error}"
            self.stop_event.wait(5)

    def discover(self):
        registry = self.lab.discover()
        self.last["discovery"] = time.time()
        self.status["discovery_at"] = registry["checked_at"]
        self.store.record("lab", "discovery", "podman ps + splunkd REST",
                          {"components": len(registry["components"]), "groups": len(registry["groups"]),
                           "relationships": len(registry["relationships"]), "errors": registry["errors"]},
                          {"component_count": len(registry["components"])}, observed_at=registry["checked_at"])

    def collect(self):
        observed_at = utc_now()
        containers = {item["name"]: item for item in self.lab.source.containers()}
        known = {item["id"] for item in self.lab.snapshot()["components"]}
        for name in sorted(known - set(containers)):
            self.store.record(name, "container", "podman ps", {"state": "missing"},
                              {"container_state": "missing"}, observed_at=observed_at)
        for name, container in containers.items():
            self.store.record(name, "container", "podman ps",
                              {key: container[key] for key in ("state", "status", "health", "started_at")},
                              {"container_state": container["state"], "container_health": container["health"]},
                              observed_at=observed_at)
        stats = self.lab.source.stats()
        for name, item in stats.items():
            if name in containers:
                self.store.record(name, "resources", "podman stats", {
                    "cpu_percent": item.get("cpu_percent") or item.get("CPU"),
                    "memory": item.get("mem_usage") or item.get("MemUsage"),
                    "memory_percent": item.get("mem_percent") or item.get("MemPerc"),
                }, observed_at=observed_at)
        splunk = [item["id"] for item in self.lab.snapshot()["components"]
                  if item["kind"] == "splunk_enterprise" and containers.get(item["id"], {}).get("state") == "running"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda name: self._collect_splunk(name, observed_at), splunk))
        self.last["health"] = time.time()
        self.status["health_at"] = observed_at

    def _collect_splunk(self, name, observed_at):
        source = self.lab.source
        status = source.web_status(name)
        self.store.record(name, "web", f"GET router /lab/{name}/en-US/account/login", {"http_status": status},
                          {"web": "available" if status and status < 500 else "unavailable"}, observed_at=observed_at)
        try:
            payload, origin = source.splunk_get(name, "/services/server/health/splunkd/details")
            content = payload["entry"][0]["content"]
            features = {}

            def walk(prefix, node):
                for key, child in (node.get("features") or {}).items():
                    label = f"{prefix}/{key}" if prefix else key
                    if child.get("health") in {"yellow", "red"} and not child.get("features"):
                        features[label] = child.get("health")
                    walk(label, child)
            walk("", content)
            self.store.record(name, "splunk_health", origin, {"health": content.get("health"), "degraded_features": features},
                              {"splunk_health": content.get("health")}, observed_at=observed_at)
        except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError) as error:
            self.store.record(name, "splunk_health", f"splunkd {name}/services/server/health/splunkd/details",
                              {"error": f"{error.__class__.__name__}: {error}"[:200]},
                              {"splunk_health": "unknown"}, observed_at=observed_at)
        try:
            payload, origin = source.splunk_get(name, "/services/messages")
            messages = sorted(({"name": entry["name"], "severity": entry["content"].get("severity"),
                                "message": (entry["content"].get("message") or "")[:300]}
                               for entry in payload.get("entry", [])), key=lambda item: item["name"])
            errors = [item for item in messages if item["severity"] in {"error", "critical"}]
            self.store.record(name, "splunk_messages", origin, {"count": len(messages), "messages": messages[:25]},
                              {"error_messages": len(errors)}, observed_at=observed_at)
        except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
            self.store.record(name, "splunk_messages", f"splunkd {name}/services/messages",
                              {"error": f"{error.__class__.__name__}"}, observed_at=observed_at)
