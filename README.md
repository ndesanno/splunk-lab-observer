# Splunk Lab Observer

A private, local web interface for seeing what is happening across a Splunk lab and working with an AI while retaining direct access to the evidence.

The agreed product direction is recorded in [the product brief](docs/PRODUCT_BRIEF.md). The first milestone covers Hindsight, Federation Pulse HQ, and Federation Pulse Spoke.

## Prepare the lab

The observer reads the lab through a loopback-only router and a read-only Splunk account. Both are set up from the lab checkout (`~/splunk-lab/lab/observer.sh`):

```sh
./observer.sh web       # each Splunk Web serves under /lab/<container>/ (restarts the lab once)
./observer.sh router    # p-observer-router on 127.0.0.1:8190: /lab/<c>/ -> Splunk Web, /mgmt/<c>/ -> splunkd
./observer.sh account   # read-only lab_observer user on every instance
./observer.sh status    # every Splunk Web and lab_observer login through the router
```

The account's password is written only to `~/.config/splunk-lab-observer/splunk.json` (mode 600). Splunk Web keeps answering on its old address: `/` redirects to `/lab/<container>/`.

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

- **Wall:** choose components, switch each between a live Splunk screen and a timestamped preview, arrange them by dragging or with the arrows, focus one, and save the layout. Live screens are full Splunk pages; sign in with your own lab account. Headless components (forwarders, load balancer, generators) show their container log and resource use.
- **Overview:** discovered components, clusters, and relationships. Every fact shows its source and check time. Your own names and descriptions are marked as labels and never replace discovered facts.
- **Changes:** state changes found by the minute-by-minute background checks, each linked to the observation that showed it.

- **Ask Claude:** a panel beside the wall where you ask about the lab or ask for something to be done. Claude investigates with read-only tools (lab registry, recorded history, splunkd REST and aggregate searches as `lab_observer`, container logs), opens the screens it is looking at in your focused view, and asks before any change. Each step shows the evidence sent to Claude. Container start, stop and restart, and Splunk changes through splunkd REST as `lab_operator` (when the lab's `./observer.sh operator` has created that account), each wait for your approval of the stated reason, effect and cleanup. For an app workflow Claude proposes a walkthrough; once you start it, Claude reads and clicks in your live view (each element is highlighted), and waits for Continue after every step. Pause or Take over holds its next action until you hand back. Runs are kept for 30 days; pick an earlier one to continue it.

- **Claude Code from the terminal:** when Claude Code works on the lab from a terminal conversation on the lab PC, it records its steps with `python -m observer.terminal` (`start`, `show <component> [path]`, `note`, `did`, `end`). An open observer page follows the live session: the panel opens, each step appears, and each screen it shows opens in your focused view. Terminal sessions are marked ⌨ in the conversation list.

Background work: discovery every 5 minutes, health (container state, Splunk health, splunkd messages, web reachability, resource use) every minute, and previews of every Splunk Web every 10 minutes. Previews are taken by a headless browser container signed in as `lab_observer`; the first run builds `localhost/lab-observer-capture`. Observations are kept for 30 days and previews for 48 hours, under `~/.local/share/splunk-lab-observer/`. Use `--no-capture` to skip previews.

## Open it from a Mac on the same LAN

On the mini PC, create a certificate for its current private IP address and an owner password. The files are created under `~/.config/splunk-lab-observer/`, outside this repository:

```sh
python3 -m observer.setup_lan --address 192.168.3.86
python3 -m observer.server --lan-address 192.168.3.86
```

The setup command prints the certificate's SHA-256 fingerprint and the path to a one-time password file. Read that file on the mini PC, save the password on your Mac, then remove the one-time file. Copy `cert.pem` to the Mac and trust it in Keychain Access only after its fingerprint matches the mini PC's output. The certificate is valid for this IP address for one year; renew it and update trust if the IP changes or the certificate expires.

On the Mac, open **https://192.168.3.86:8765/observer/** and sign in with the observer password. Splunk then presents its own normal login inside the view. The observer listens only on the named private IP and port; this setup does not add router port forwarding. The LAN listener uses Python's small HTTP server behind TLS and is intended for this trusted home network.

Run the HTTP integration checks with:

```sh
python3 -m unittest discover -s tests
```
