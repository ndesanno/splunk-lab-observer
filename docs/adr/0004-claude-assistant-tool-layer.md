# Let Claude reach the lab only through audited, observer-side tools

The owner asks Claude about the lab, or asks it to act, from a panel beside the wall. Claude runs on the observer, not in the browser: the server calls the Claude API (`claude-opus-5-5`, adaptive thinking, server-side refusal fallback) through the official `anthropic` SDK's tool runner, and the page polls the run's trail.

Claude never receives lab credentials or a shell. It gets a small set of tools, each of which the observer executes and records: the tool, its input, the account or command used, the time, and the exact text returned to the model. The owner reads that text under "Evidence sent to Claude". Read-only tools use the `lab_observer` account. A search must aggregate, and `_raw` fields are dropped from search and REST results, so raw event text stays on the workstation. REST reads refuse search-job and stored-password endpoints, and secret-looking text is masked in container logs.

`show_screen` is how Claude shows the owner what it is doing: it adds a display step that the page turns into focusing that component and opening the named Splunk Web path in the live view the owner already controls. Claude cannot click or type in Splunk Web in this version.

The only tool that changes the lab, `container_action` (podman start, stop, restart), blocks until the owner approves a card that states the reason, the expected effect, and the cleanup. Declining, stopping the run, or 15 minutes without a decision returns that outcome to Claude and changes nothing. Each approved change is recorded as an observation, and the run ends with a summary that lists any container still stopped. Changes that need splunkd write access wait for a dedicated operator account that the owner creates on purpose.

The API key is entered in the panel and stored in a mode-600 file in the observer's config directory (or taken from `ANTHROPIC_API_KEY`); it is never returned by the API. The SDK is an optional dependency, so the rest of the observer still runs on the standard library.
