# Splunk Lab Observer

A private, local web interface for seeing what is happening across a Splunk lab and working with an AI while retaining direct access to the evidence.

The agreed product direction is recorded in [the product brief](docs/PRODUCT_BRIEF.md). The first milestone covers Hindsight, Federation Pulse HQ, and Federation Pulse Spoke.

## Run the first component view

From this checkout:

```sh
python3 -m observer.server
```

Open <http://127.0.0.1:8765/observer/>. The first view shows the lab Monitoring Console on port 8100. Log in through the displayed Splunk screen with your normal lab account. The observer runs only on loopback and does not store credentials.

Use `--port` to change the observer port or `--component-url http://127.0.0.1:PORT` to select another loopback Splunk web endpoint. The first slice displays one component; the approved [ticket plan](https://github.com/ndesanno/splunk-lab-observer/issues/1) adds discovery and a selectable wall of views.

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
