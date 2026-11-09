"""Timestamped screen previews of every Splunk Web, taken by a headless browser.

Previews let the wall show many components without keeping every screen live. One
Playwright container signs in to each Splunk Web as the observer's read-only account
and saves a screenshot; each one is stored as an observation with its capture time.
"""

import json
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from observer.store import utc_now


BASE_IMAGE = "mcr.microsoft.com/playwright/python:v1.48.0-jammy"
IMAGE = "localhost/lab-observer-capture:1.48.0"
SCRIPT = Path(__file__).with_name("capture_browser.py")
CAPTURE_INTERVAL_SECONDS = 10 * 60
KEEP_SECONDS = 48 * 60 * 60


class Capture:
    def __init__(self, lab, store, data_dir):
        self.lab = lab
        self.store = store
        self.directory = Path(data_dir) / "captures"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.status = {"running": False, "last_run_at": None, "last_error": None}

    def start(self):
        threading.Thread(target=self._loop, name="observer-capture", daemon=True).start()

    def stop(self):
        self.stop_event.set()

    def _loop(self):
        self.stop_event.wait(30)  # let discovery run first
        while not self.stop_event.is_set():
            self.run()
            self.stop_event.wait(CAPTURE_INTERVAL_SECONDS)

    def _ensure_image(self):
        if subprocess.run(["podman", "image", "exists", IMAGE]).returncode == 0:
            return
        containerfile = f"FROM {BASE_IMAGE}\nRUN pip install --no-cache-dir playwright==1.48.0\n"
        subprocess.run(["podman", "build", "-q", "-t", IMAGE, "-f", "-", str(SCRIPT.parent)],
                       input=containerfile, text=True, capture_output=True, check=True, timeout=900)

    def run(self, components=None):
        """Capture the given components (default: every Splunk Web). Returns the results."""
        if not self.lock.acquire(blocking=False):
            return {"started": False, "reason": "a capture is already running"}
        self.status["running"] = True
        results = []
        try:
            targets = sorted(components or self.lab.web_components())
            if not targets:
                return {"started": False, "reason": "no Splunk Web components discovered yet"}
            self._ensure_image()
            # The credential file stays outside the served captures directory and lives only for this run.
            with tempfile.NamedTemporaryFile("w", dir=self.directory.parent, prefix=".capture-env-", delete=False) as env:
                os.chmod(env.name, 0o600)
                env.write(f"OBSERVER_USER={self.lab.source.username}\nOBSERVER_PASSWORD={self.lab.source.password_for_capture()}\n")
            try:
                result = subprocess.run(
                    ["podman", "run", "--rm", "--network", "host", "--memory", "1500m", "--env-file", env.name,
                     "-v", f"{SCRIPT}:/capture_browser.py:ro,Z", "-v", f"{self.directory}:/out:Z",
                     IMAGE, "python3", "/capture_browser.py", self.lab.source.router, *targets],
                    capture_output=True, text=True, timeout=60 * len(targets) + 120)
            finally:
                os.unlink(env.name)
            for line in result.stdout.splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                results.append(item)
                source = f"headless Chromium as {self.lab.source.username} via router /lab/{item['component']}/"
                if item.get("file"):
                    self.store.record(item["component"], "capture", source,
                                      {"file": item["file"], "page": item.get("page"), "title": item.get("title")},
                                      {"capture": "captured"}, observed_at=item["captured_at"])
                else:
                    self.store.record(item["component"], "capture", source, {"error": item.get("error")},
                                      {"capture": "failed"}, observed_at=item["captured_at"])
            if result.returncode != 0 and not results:
                self.status["last_error"] = result.stderr.strip()[-300:]
            self.status["last_run_at"] = utc_now()
            return {"started": True, "results": results}
        except (OSError, subprocess.SubprocessError) as error:
            self.status["last_error"] = f"{error.__class__.__name__}: {error}"[:300]
            return {"started": False, "reason": self.status["last_error"]}
        finally:
            self.status["running"] = False
            self.lock.release()

    def screenshot(self, component, screen, directory):
        """One screenshot of a chosen page, saved under `directory` (a run's evidence folder), not the preview cache."""
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._ensure_image()
        with tempfile.NamedTemporaryFile("w", dir=self.directory.parent, prefix=".capture-env-", delete=False) as env:
            os.chmod(env.name, 0o600)
            env.write(f"OBSERVER_USER={self.lab.source.username}\nOBSERVER_PASSWORD={self.lab.source.password_for_capture()}\n")
        try:
            result = subprocess.run(
                ["podman", "run", "--rm", "--network", "host", "--memory", "1500m", "--env-file", env.name,
                 "-v", f"{SCRIPT}:/capture_browser.py:ro,Z", "-v", f"{directory}:/out:Z",
                 IMAGE, "python3", "/capture_browser.py", self.lab.source.router, f"{component}::{screen}"],
                capture_output=True, text=True, timeout=180)
        finally:
            os.unlink(env.name)
        for line in result.stdout.splitlines():
            try:
                return json.loads(line)
            except ValueError:
                continue
        raise RuntimeError(result.stderr.strip()[-300:] or "no screenshot")

    def path_for(self, file_name):
        """Resolve a capture file name from an observation, refusing anything outside the directory."""
        path = (self.directory / file_name).resolve()
        if path.suffix != ".jpg" or not path.is_relative_to(self.directory.resolve()) or not path.is_file():
            return None
        return path

    def prune(self, now=None):
        cutoff = (now or time.time()) - KEEP_SECONDS
        for component in self.directory.iterdir():
            if not component.is_dir():
                continue
            files = sorted(component.glob("*.jpg"))
            for path in files[:-1]:  # always keep the newest preview
                if path.stat().st_mtime < cutoff:
                    path.unlink()
