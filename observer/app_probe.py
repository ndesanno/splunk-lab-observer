"""Runs inside a Splunk container (Splunk's Python) to list installed apps and their screens.

Read-only: it reads app.conf, navigation menus, and view labels under etc/apps and prints JSON.
The observer passes this file's source to `splunk cmd python3 -c`.
"""

import configparser
import json
import os
import re

APPS = "/opt/splunk/etc/apps"


def conf(app):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    for layer in ("default", "local"):
        try:
            parser.read(os.path.join(APPS, app, layer, "app.conf"), encoding="utf-8")
        except (configparser.Error, UnicodeDecodeError):
            pass
    return parser


def layered(app, *parts):
    for layer in ("local", "default"):
        path = os.path.join(APPS, app, layer, *parts)
        if os.path.exists(path):
            return path
    return None


def view_labels(app):
    labels = {}
    for layer in ("default", "local"):
        directory = os.path.join(APPS, app, layer, "data", "ui", "views")
        for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
            if not name.endswith((".xml", ".html")):
                continue
            try:
                with open(os.path.join(directory, name), encoding="utf-8", errors="replace") as handle:
                    head = handle.read(4096)
            except OSError:
                continue
            match = re.search(r"<label>(.*?)</label>", head, re.S)
            labels[name.rsplit(".", 1)[0]] = match.group(1).strip() if match else None
    return labels


def main():
    apps = []
    for app in sorted(os.listdir(APPS)):
        if not os.path.isdir(os.path.join(APPS, app)):
            continue
        parser = conf(app)
        get = lambda section, key: parser.get(section, key, fallback=None)
        nav_path = layered(app, "data", "ui", "nav", "default.xml")
        nav = None
        if nav_path:
            with open(nav_path, encoding="utf-8", errors="replace") as handle:
                nav = handle.read(65536)
        apps.append({
            "app": app,
            "label": get("ui", "label"),
            "visible": (get("ui", "is_visible") or "false").strip().lower() in {"1", "true", "yes"},
            "disabled": (get("install", "state") or "").strip().lower() == "disabled",
            "version": get("launcher", "version") or get("id", "version"),
            "build": get("install", "build"),
            "nav": nav,
            "views": view_labels(app),
        })
    print(json.dumps(apps))


main()
