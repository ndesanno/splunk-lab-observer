"""Runs inside the capture container: sign in to each Splunk Web and save a screenshot.

argv: <router URL> <component>...; credentials arrive in the environment from a mode-600 file.
Prints one JSON line per component and never prints the password.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def capture(browser, router, component):
    base = f"{router}/lab/{component}"
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    try:
        page.goto(f"{base}/en-US/account/login?return_to=/lab/{component}/en-US/app/launcher/home", timeout=30000)
        if page.locator("#username").count():
            page.fill("#username", os.environ["OBSERVER_USER"])
            page.fill("#password", os.environ["OBSERVER_PASSWORD"])
            page.locator("input[type=submit], button[type=submit]").first.click()
        try:
            page.wait_for_load_state("networkidle", timeout=20000)
        except Exception:
            pass
        # Splunk's one-time product notices cover the screen; close them if present.
        for label in ("Got it", "Skip", "Don't show me this again"):
            button = page.get_by_role("button", name=label)
            if button.count():
                button.first.click()
                page.wait_for_timeout(500)
        captured_at = now()
        name = f"{component}/{int(time.time() * 1000)}.jpg"
        Path("/out", component).mkdir(exist_ok=True)
        page.screenshot(path=f"/out/{name}", type="jpeg", quality=60)
        path = page.url.split(f"/lab/{component}", 1)[-1]
        return {"component": component, "captured_at": captured_at, "file": name, "page": path, "title": page.title()}
    except Exception as error:
        return {"component": component, "captured_at": now(), "error": f"{error.__class__.__name__}: {str(error)[:200]}"}
    finally:
        context.close()


def main():
    router, components = sys.argv[1], sys.argv[2:]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for component in components:
            print(json.dumps(capture(browser, router, component)), flush=True)
        browser.close()


if __name__ == "__main__":
    main()
