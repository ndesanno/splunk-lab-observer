# Splunk Lab Observer

A private, local web interface for seeing what is happening across a Splunk lab and working with an AI while retaining direct access to the evidence. It runs on the machine that hosts the lab, for one owner, and can be opened from another computer on the same private network.

The product direction is recorded in [the product brief](docs/PRODUCT_BRIEF.md), the terms in [the glossary](GLOSSARY.md), and the design decisions in [docs/adr/](docs/adr/).

## Requirements

- Linux with Python 3.11 or later and [podman](https://podman.io/).
- A Splunk lab running as podman containers on one podman network: Splunk Enterprise from the `splunk/splunk` image (Splunk Web on port 8000 and splunkd on 8089 inside each container), and optionally universal forwarders, load balancers and data generators. Container names become the observer's component ids.
- The lab's Splunk admin password, used once by the setup script below and never stored by it.
- Optional: an Anthropic API key for the Ask Claude panel.

## Prepare the lab

The observer reads the lab through a loopback-only router and a read-only Splunk account. [`lab-setup/observer-lab.sh`](lab-setup/observer-lab.sh) sets both up; tell it which podman network the lab uses:

```sh
export LAB_NETWORK=my-splunk-lab   # the podman network your Splunk containers share
lab-setup/observer-lab.sh web       # each Splunk Web serves under /lab/<container>/; then restart those instances
lab-setup/observer-lab.sh router    # observer-router on 127.0.0.1:8190: /lab/<c>/ -> Splunk Web, /mgmt/<c>/ -> splunkd
lab-setup/observer-lab.sh account   # read-only lab_observer role and user on every instance
lab-setup/observer-lab.sh status    # every Splunk Web and lab_observer login through the router
```

`account` asks for the admin password (or reads `SPLUNK_ADMIN_PASSWORD`) and passes it to curl inside each container on stdin, never on a command line. It generates the `lab_observer` password and writes it, with the router address and the network, only to `~/.config/splunk-lab-observer/splunk.json` (mode 600). Splunk Web keeps answering on its old address: `/` redirects to `/lab/<container>/`. Run `router` again after adding Splunk containers. The script's header lists every setting, including `SPLUNK_CONTAINERS` to choose the instances yourself.

`lab-setup/observer-lab.sh operator` optionally adds a `lab_operator` account with the admin role. The observer uses it only for changes you approve one at a time (see Ask Claude below), and keeps its password in `~/.config/splunk-lab-observer/operator.json` (mode 600).

## Run the observer

From this checkout:

```sh
python3 -m observer.server
```

To use Ask Claude, run the observer with the Anthropic SDK installed, for example in a virtual environment (Debian's Python has no `ensurepip`, so bootstrap pip with `get-pip.py` if `python3 -m venv` leaves none):

```sh
python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m observer.server
```

Then open the panel and paste an Anthropic API key. It is saved in `~/.config/splunk-lab-observer/anthropic.json` (mode 600) and never shown again; `ANTHROPIC_API_KEY` works too.

Open <http://127.0.0.1:8765/observer/>.

- **Wall:** choose components, switch each between a live Splunk screen and a timestamped preview, arrange them by dragging or with the arrows, focus one, and save the layout. Live screens are full Splunk pages; sign in with your own lab account, or use "Sign in live views" to sign every live view in as the test account. Focusing a live view keeps its page: the same frame is enlarged, with its current path, back and reload above it. A live view reopens on the screen it last showed, and the focused view is kept in the address so a reload or bookmark returns to it. Headless components (forwarders, load balancer, generators) show their container log and resource use.
- **Overview:** discovered components, clusters, and relationships. Every fact shows its source and check time. Your own names and descriptions are marked as labels and never replace discovered facts.
- **Coverage:** each app's screens, panels, page sections, actions, saved searches, commands, REST handlers, inputs and KV collections, read from the app's source at the ref matching the installed version and build, against six cases (normal, empty, incorrect, permission, error, recovery). The installed version on each component is shown next to the source version. Pass and fail link to the run and steps that show them. List app sources in `~/.config/splunk-lab-observer/coverage-sources.json` (see `observer/coverage.py`).
- **Changes:** state changes found by the minute-by-minute background checks, each linked to the observation that showed it.

- **Ask Claude:** a panel beside the wall where you ask about the lab or ask for something to be done. Claude investigates with read-only tools (lab registry, recorded history, splunkd REST and aggregate searches as `lab_observer`, container logs), opens the screens it is looking at in your focused view, and asks before any change. Each step shows the evidence sent to Claude. Container start, stop and restart, and Splunk changes through splunkd REST as `lab_operator` (when `lab-setup/observer-lab.sh operator` has created that account), each wait for your approval of the stated reason, effect and cleanup. For an app workflow Claude proposes a walkthrough; once you start it, Claude reads and clicks in your live view (each element is highlighted), and waits for Continue after every step. Pause or Take over holds its next action until you hand back. Each run keeps a record: the lab's versions and state when it started, every step, screenshots, failures, and Claude's verdict for a test, downloadable as JSON. Runs and their screenshots are kept for 30 days unless you pin them. Pick an earlier run to continue it.

- **Checks:** comparisons between what an app shows and an independent reading of the same fact (Splunk's own index list, server GUID, member list, installed versions). The observer runs them itself as the read-only account, without an AI model, ten minutes after it starts and then every six hours, and you can run one or all from the Checks tab. Each result is pass, fail or unverified, links to the readings it rests on, and marks the matching coverage case. A reading that cannot be taken is unverified, never passed. Checks ship in `observer/checks/*.json`; add your own in `~/.config/splunk-lab-observer/checks.json` (format in `observer/checks.py`). One example ships in `observer/checks/example.json`. The read account must be able to see each app's saved searches and lookups: add the app's own read-only role, if it has one, to the `lab_observer` role.
- **Fixture runs:** some features can only be checked with data the lab does not hold. A fixture adds clearly named test data through an app's own handler as `lab_operator`, reads what the app then shows as the read-only account (normal, empty, bad input, no permission, recovery), and removes the data again, whatever happens. It changes the lab, so it runs only with the owner's agreement, and it is kept as a run with coverage marks. No fixture ships with the observer; write one per app with `observer.assistant.Run` for the record and `observer.lab.OperatorAccount` for the change.
- **Claude Code from the terminal:** when Claude Code works on the lab from a terminal conversation on the lab PC, it records its steps with `python -m observer.terminal` (`start`, `show <component> [path]`, `note`, `did`, `coverage`, `end`). With `signin`, `read`, `click`, `type`, `select` and `upload` it works in your focused view as the test account, so you watch the same session; these fail when no observer page is open. `upload` takes a package from `~/.local/share/splunk-lab-observer/packages/`. An open observer page follows the live session: the panel opens, each step appears, and each screen it shows opens in your focused view. Terminal sessions are marked ⌨ in the conversation list.

Background work: discovery every 5 minutes, health (container state, Splunk health, splunkd messages, web reachability, resource use) every minute, and previews of every Splunk Web every 10 minutes. Previews are taken by a headless browser container signed in as `lab_observer`; the first run builds `localhost/lab-observer-capture`. Observations are kept for 30 days and previews for 48 hours, under `~/.local/share/splunk-lab-observer/`. Use `--no-capture` to skip previews.

## Open it from another computer on the same LAN

The examples use `192.168.1.50` for the lab machine's private address; use your own. On the lab machine, create a certificate for its current private IP address and an owner password. The files are created under `~/.config/splunk-lab-observer/`, outside this repository:

```sh
python3 -m observer.setup_lan --address 192.168.1.50
python3 -m observer.server --lan-address 192.168.1.50
```

The setup command prints the certificate's SHA-256 fingerprint and the path to a one-time password file. Read that file on the lab machine, save the password on the other computer, then remove the one-time file. Copy `cert.pem` to that computer and trust it (on a Mac, in Keychain Access) only after its fingerprint matches the lab machine's output. The certificate is valid for this IP address for one year; renew it and update trust if the IP changes or the certificate expires.

On that computer, open **https://192.168.1.50:8765/observer/** and sign in with the observer password. Splunk then presents its own normal login inside the view. The observer listens only on the named private IP and port; this setup does not add router port forwarding. The LAN listener uses Python's small HTTP server behind TLS and is intended for a trusted private network.

Trusting the certificate matters for speed as well as for the warning: a browser that does not trust it keeps no cache, and every Splunk page then downloads all of its files again. The wall shows a notice when it sees that happening.

## Start it with the workstation

```sh
.venv/bin/python -m observer.service install --lan-address 192.168.1.50 --port 8766
sudo loginctl enable-linger "$USER"   # once, so it starts at boot and not only when you sign in
```

This writes a systemd user service for this checkout (`journalctl --user -u splunk-lab-observer.service` for its log). `python -m observer.service remove` takes it out again. Start the lab itself as you normally do; the router container keeps running across observer restarts (recreate it with `lab-setup/observer-lab.sh router`).

Ask Claude uses `claude-opus-5-5`; set `OBSERVER_CLAUDE_MODEL` in the observer's environment to use another model id.

Run the tests with:

```sh
.venv/bin/python -m unittest discover -s tests
```

The tests of the page itself (`tests/test_page.py`) drive it in the preview-capture browser image and are skipped where podman or that image is missing. The assistant's tests are skipped without the `anthropic` package.
