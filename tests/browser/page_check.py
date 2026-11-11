"""Runs inside the capture container: drive the observer page in headless Chromium and print what it saw.

argv: <observer URL>. Prints one JSON object; the unittest that started the observer asserts on it.
"""

import json
import sys

from playwright.sync_api import sync_playwright

BASE = sys.argv[1]
RICH = "/en-US/app/search/rich"
out = {"errors": []}

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 1600, "height": 1000})
    page.on("pageerror", lambda error: out["errors"].append(str(error)[:300]))
    page.goto(f"{BASE}/observer/")
    page.wait_for_selector(".tile iframe", timeout=15000)
    live = page.evaluate("layout.tiles.find(tile => tile.live).id")
    preview = page.evaluate("layout.tiles.find(tile => !tile.live).id")
    out["live_tiles"] = page.locator(".tile iframe").count()
    frame = lambda: page.frame_locator(".tile iframe").first
    page.wait_for_function("framePath(document.querySelector('.tile iframe'), byId(layout.tiles[0].id)) !== ''")
    page.evaluate("document.querySelector('.tile iframe').contentWindow.marker = 'kept'")

    # Focus the live tile: the same frame, not reloaded, laid over the page.
    page.locator(f".tile[data-id='{live}'] button[title^='Focus']").click()
    page.wait_for_selector(".tile.focused")
    page.wait_for_timeout(300)
    box = page.locator(".tile.focused").bounding_box()
    out["focus"] = {"marker": page.evaluate("focusFrame().contentWindow.marker"), "width": box["width"], "height": box["height"],
                    "frames": page.locator("iframe").count(), "hash": page.evaluate("location.hash"),
                    "mode": page.locator(".focus").get_attribute("data-mode")}

    # Open a screen in it: the address shown follows, and the screen is remembered.
    page.evaluate(f"showScreen('{live}', '{RICH}')")
    page.wait_for_function(f"document.getElementById('view-path').textContent === '{RICH}'", timeout=10000)
    out["path"] = {"shown": page.locator("#view-path").inner_text(), "open_href": page.locator("#view-open").get_attribute("href"),
                   "remembered": page.evaluate(f"localStorage.getItem('screen:{live}')")}

    reading = page.evaluate("snapshot(focusFrame())")
    out["reading"] = {"text": reading["text"], "labels": [item["label"] for item in reading["elements"]], "omitted": reading["omitted"]}

    # Close: still the same frame, back in the wall.
    page.evaluate("focusFrame().contentWindow.marker = 'kept again'")
    page.keyboard.press("Escape")
    page.wait_for_selector(".tile.focused", state="detached")
    out["closed"] = {"marker": page.evaluate("document.querySelector('.tile iframe').contentWindow.marker"),
                     "hash": page.evaluate("location.hash"), "focus_overlay": page.locator(".focus").count(),
                     "tile_position": page.evaluate(f"getComputedStyle(document.querySelector(\".tile[data-id='{live}']\")).position")}

    # A preview tile gets its own live frame while focused.
    page.locator(f".tile[data-id='{preview}'] button[title^='Focus']").click()
    page.wait_for_selector(".focus iframe")
    out["preview_focus"] = {"mode": page.locator(".focus").get_attribute("data-mode"), "hash": page.evaluate("location.hash")}
    page.keyboard.press("Escape")

    # Reload with the address of a focused view: it comes back focused, on the remembered screen.
    page.goto(f"{BASE}/observer/#focus={live}")
    page.reload()
    page.wait_for_selector(".tile.focused iframe", timeout=15000)
    out["deep_link"] = {"src": page.locator(".tile.focused iframe").get_attribute("src"), "focused": page.evaluate("focused")}
    browser.close()

print(json.dumps(out))
