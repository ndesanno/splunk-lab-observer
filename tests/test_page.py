"""The observer page itself, driven in a headless browser against a fake lab.

Needs podman and the preview-capture image; skipped where they are missing.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from observer.capture import IMAGE
from observer.lab import Lab
from observer.server import create_server
from observer.store import Store
from tests.fakes import FakeSource, start, start_router


def image_available():
    try:
        return subprocess.run(["podman", "image", "exists", IMAGE], timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(image_available(), f"needs podman and the {IMAGE} image")
class PageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.router = start_router()
        cls.store = Store(cls.temp.name)
        cls.lab = Lab(FakeSource(), cls.store)
        cls.lab.discover()
        cls.observer = start(create_server(("127.0.0.1", 0), f"http://127.0.0.1:{cls.router.server_port}", lab=cls.lab, store=cls.store))
        script = Path(__file__).with_name("browser")
        done = subprocess.run(["podman", "run", "--rm", "--network", "host", "-v", f"{script}:/browser:ro", IMAGE,
                               "python", "/browser/page_check.py", f"http://127.0.0.1:{cls.observer.server_port}"],
                              capture_output=True, text=True, timeout=180)
        cls.output = done.stdout.strip().splitlines()[-1] if done.stdout.strip() else ""
        cls.problem = done.stderr[-1500:]

    @classmethod
    def tearDownClass(cls):
        cls.observer.shutdown(); cls.observer.server_close(); cls.router.shutdown(); cls.router.server_close()
        cls.store.db.close(); cls.temp.cleanup()

    def setUp(self):
        self.assertTrue(self.output.startswith("{"), self.problem)
        self.seen = json.loads(self.output)

    def test_the_page_runs_without_script_errors(self):
        self.assertEqual(self.seen["errors"], [])

    def test_focusing_a_live_view_keeps_its_page_and_closing_returns_it(self):
        focus = self.seen["focus"]
        self.assertEqual((focus["marker"], focus["mode"], focus["frames"]), ("kept", "tile", self.seen["live_tiles"]))
        self.assertGreater(focus["width"], 900)
        self.assertGreater(focus["height"], 600)
        self.assertIn("focus=", focus["hash"])
        closed = self.seen["closed"]
        self.assertEqual((closed["marker"], closed["hash"], closed["focus_overlay"]), ("kept again", "", 0))
        self.assertNotEqual(closed["tile_position"], "fixed")
        self.assertEqual(self.seen["preview_focus"]["mode"], "own")

    def test_the_view_shows_where_it_is_and_comes_back_there(self):
        path = self.seen["path"]
        self.assertEqual((path["shown"], path["remembered"]), ("/en-US/app/search/rich", "/en-US/app/search/rich"))
        self.assertTrue(path["open_href"].endswith("/en-US/app/search/rich"))
        deep = self.seen["deep_link"]
        self.assertTrue(deep["src"].endswith("/en-US/app/search/rich"), deep)
        self.assertTrue(deep["focused"])

    def test_a_reading_holds_only_what_is_on_screen(self):
        reading = self.seen["reading"]
        self.assertIn("Visible heading", reading["text"])
        self.assertIn("Results ready", reading["text"])  # inline pieces stay on one line
        for hidden in ("Hidden banner", "Hidden menu", "Invisible note", "raw event text", "alice", "secret", "hiddenScriptText"):
            self.assertNotIn(hidden, reading["text"])
        self.assertEqual(reading["labels"][:2], ["Save As", "Datasets"])
        self.assertIn("raw event", reading["omitted"])


if __name__ == "__main__":
    unittest.main()
