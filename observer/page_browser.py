"""Runs inside the capture container: open Splunk Web pages and report what each one shows.

argv: <router URL> <path of a JSON file>; the file holds a list of
{"key", "component", "path", "find": [regular expressions], "wait": seconds}. Each page is opened
signed in as the observer's read-only account (credentials arrive in the environment from a
mode-600 file) and its visible text is searched once the page has settled. Prints one JSON line
per page and never prints the password.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

from playwright.sync_api import sync_playwright


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sign_in(context, router, component):
    page = context.new_page()
    page.goto(f"{router}/lab/{component}/en-US/account/login", timeout=30000)
    if page.locator("#username").count():
        page.fill("#username", os.environ["OBSERVER_USER"])
        page.fill("#password", os.environ["OBSERVER_PASSWORD"])
        page.locator("input[type=submit], button[type=submit]").first.click()
        page.wait_for_url(lambda url: "account/login" not in url, timeout=30000)
    return page


QUIET_SECONDS = 4  # a dashboard polls its search jobs about once a second while they run
STABLE_READS = 3


def read(page, router, target, activity):
    """The first group of each expression in the page's visible text. A dashboard shows placeholder
    values while its searches run, so the values count only once they have stopped changing and the
    page has stopped asking splunkd about searches."""
    activity["at"] = time.time()
    page.goto(f"{router}/lab/{target['component']}{target['path']}", timeout=30000)
    deadline = time.time() + target.get("wait", 60)
    text, values, same = "", [], 0
    while True:
        text = re.sub(r"\s+", " ", page.inner_text("body"))
        found = [re.search(expression, text) for expression in target["find"]]
        before, values = values, [match.group(1) if match and match.groups() else match.group(0) if match else None for match in found]
        same = same + 1 if values == before else 1
        settled = same >= STABLE_READS and time.time() - activity["at"] >= QUIET_SECONDS
        if all(value is not None for value in values) and settled:
            break
        if time.time() > deadline:
            values = [value if settled else None for value in values]
            break
        page.wait_for_timeout(1000)
    result = {"key": target["key"], "read_at": now(), "values": values, "title": page.title(),
              "url": page.url.split(f"/lab/{target['component']}", 1)[-1]}
    if "account/login" in page.url:
        result["error"] = "the page asked the read-only account to sign in again"
    elif any(value is None for value in values):
        missing = [expression for expression, value in zip(target["find"], values) if value is None]
        result["error"] = f"the page did not settle on a value for {', '.join(missing)} within {target.get('wait', 60)} s"
        result["text"] = text[:600]
    return result


def main():
    router, targets = sys.argv[1], json.load(open(sys.argv[2], encoding="utf-8"))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        pages = {}
        for target in targets:
            try:
                if target["component"] not in pages:
                    context = browser.new_context(viewport={"width": 1440, "height": 900})
                    page = sign_in(context, router, target["component"])
                    activity = {"at": time.time()}
                    page.on("request", lambda request, seen=activity: seen.update(at=time.time())
                            if "/search/" in request.url or "/splunkd/" in request.url else None)
                    pages[target["component"]] = (page, activity)
                result = read(*pages[target["component"]][:1], router, target, pages[target["component"]][1])
            except Exception as error:
                result = {"key": target["key"], "read_at": now(), "values": [],
                          "error": f"{error.__class__.__name__}: {str(error)[:200]}"}
            print(json.dumps(result), flush=True)
        browser.close()


if __name__ == "__main__":
    main()
