"""Run the observer as a systemd user service, so it comes back after a restart of the workstation.

    python -m observer.service install --lan-address 192.168.3.86 --port 8766
    python -m observer.service remove

install writes ~/.config/systemd/user/splunk-lab-observer.service for this checkout and this Python,
enables it, and starts it. The service starts at boot only if the user may run services without
being signed in ("linger"); install says whether that is on and how to turn it on.
"""

import argparse
import subprocess
import sys
from pathlib import Path

NAME = "splunk-lab-observer.service"
UNIT_DIR = Path.home() / ".config" / "systemd" / "user"


def unit_text(python, checkout, arguments):
    command = " ".join([str(python), "-m", "observer.server", *arguments])
    return f"""[Unit]
Description=Splunk Lab Observer
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory={checkout}
ExecStart={command}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"""


def systemctl(*arguments):
    return subprocess.run(["systemctl", "--user", *arguments], capture_output=True, text=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the observer as a systemd user service")
    actions = parser.add_subparsers(dest="action", required=True)
    install = actions.add_parser("install")
    install.add_argument("--lan-address")
    install.add_argument("--port", type=int, default=8765)
    install.add_argument("--no-capture", action="store_true")
    actions.add_parser("remove")
    args = parser.parse_args(argv)
    unit = UNIT_DIR / NAME
    if args.action == "remove":
        systemctl("disable", "--now", NAME)
        unit.unlink(missing_ok=True)
        systemctl("daemon-reload")
        print(f"Removed {unit}")
        return 0
    arguments = ["--port", str(args.port)]
    if args.lan_address:
        arguments += ["--lan-address", args.lan_address]
    if args.no_capture:
        arguments.append("--no-capture")
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    unit.write_text(unit_text(Path(sys.executable), Path(__file__).resolve().parent.parent, arguments))
    systemctl("daemon-reload")
    started = systemctl("enable", "--now", NAME)
    if started.returncode:
        print(started.stderr.strip(), file=sys.stderr)
        return 1
    print(f"Wrote {unit} and started it. Logs: journalctl --user -u {NAME}")
    linger = subprocess.run(["loginctl", "show-user", Path.home().name, "-p", "Linger", "--value"], capture_output=True, text=True)
    if linger.stdout.strip() != "yes":
        print("It will start when you sign in. To start it at boot, run once: loginctl enable-linger")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
