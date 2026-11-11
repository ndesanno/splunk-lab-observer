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

Run the HTTP integration checks with:

```sh
python3 -m unittest discover -s tests
```
