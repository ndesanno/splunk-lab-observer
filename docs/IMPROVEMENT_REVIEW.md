# Design and architecture review (2026-11-11)

A review of the whole project against the spec (#1), the tickets (#2 to #22), the decisions in `docs/adr/`, and the code on `feature/claude-assistant` at commit `a815a84`. It was written so that another agent can pick up any item without the conversation that produced it. Nothing in the code was changed for this review.

Read `AGENTS.md`, `docs/PRODUCT_BRIEF.md`, `GLOSSARY.md` and the ADRs first. Issue numbers below are GitHub issue numbers; ticket titles carry a different number (issue #22 is titled "20", issue #3 is titled "02"), so always quote the issue number.

## 1. Where the project stands

| Area | Issues | State |
|---|---|---|
| First view, discovery, health, wall, screens and replay | #2 #3 #4 #5 #6 | Built, in PRs #21 and #24. Issues still open, acceptance boxes unticked. |
| LAN HTTPS and login | #22 | Built, in PR #23. Issue still open. |
| AI investigation, walkthrough, approved change, evidence, coverage map | #7 #8 #9 #10 #11 | Built, in PR #25. #7 and #9 are only partly met (section 6). |
| App checks: Hindsight, Pulse Spoke, Pulse HQ, dataset trace | #12 to #19 | Not started. No coverage mark has been recorded on the live store. |
| Scheduled smoke checks | #20 | Not started. |

- Four stacked pull requests (#21, #23, #24, #25) are open and none is merged. `main` holds none of the product.
- The live build runs from this worktree on `https://192.168.3.86:8766`. The README still says 8765.
- 46 tests pass under `.venv/bin/python`. Five test classes are skipped when the `anthropic` package is missing.

## 2. Measurements behind the performance findings

Taken on the mini PC with headless Chromium 1.48 (the capture image), page `p-hq-sh1`. "Settled" is the end of the first burst of requests. Scripts were throwaway; the method is: sign in, load the page three times, read `performance.getEntriesByType('resource')`.

| Case | Settled | Transferred | New connections |
|---|---|---|---|
| Search page, direct through the router, repeat load | 3.9 s | 0.2 MB | 0 |
| Search page, through the observer, certificate trusted, repeat load | 3.8 s | 0.2 MB | 53 to 59 |
| Search page, through the observer, certificate warning clicked through, repeat load | 3.9 s | 3.9 MB | 55 to 63 |
| Pulse HQ overview, direct, repeat load | 5.9 s | 0.2 MB | 0 |
| Pulse HQ overview, through the observer, trusted, repeat load | 5.9 s | 0.2 MB | 66 |
| Wall with 4 live tiles | 3.8 to 4.2 s each | | |
| Wall with 8 live tiles | 4.1 to 6.0 s each | | |

- On the mini PC the proxy adds almost nothing. Splunk Web itself takes 4 to 6 seconds.
- An untrusted certificate stops Chromium from caching, so every load re-downloads 3 to 4 MB.
- The observer answers HTTP/1.0 with `Connection: close`, so each request is a new TCP and TLS connection.
- Not measured: the same loads from the Mac over Wi-Fi, and Safari's caching behaviour. Both matter and should be measured before and after any proxy change.
- Host headroom at the time: 16 CPUs at load 1.7, 25 GB of 51 GB free, no swap in use. More CPU or RAM is unlikely to help page loads.
- Observer payloads: the page is 109 KB and `/observer/api/lab` is 174 KB, both uncompressed, the second fetched every 20 seconds per open page.

## 3. Architecture findings

Ordered by how much they limit the project. Each has a suggested direction, not a finished design.

### 3.1 The web server is the weakest layer

`observer/server.py` uses `ThreadingHTTPServer` with one handler class.

- **No keep-alive.** `protocol_version` is the default HTTP/1.0 and the proxy sends `Connection: close`. Fix: HTTP/1.1, pass through `Content-Length` or re-chunk, keep the client connection open, and pool upstream connections to the router.
- **TLS handshake on the accept loop.** The listening socket is wrapped, so each handshake runs in the single accept thread. One slow or stalled client delays every other connection. Fix: accept plain sockets and wrap inside the handler thread, with a handshake timeout.
- **Listen queue of 5.** `request_queue_size` is the default. Raise it.
- **Everything is `no-store` and uncompressed.** Serve the page and static assets with an ETag, and gzip JSON and HTML.
- **One origin, HTTP/1.x.** All 19 Splunk Webs and the observer share six browser connections. HTTP/2 would remove that limit but Python's standard library cannot serve it.
- **Routing is one long `if/elif` chain** (`_observer_route`, `_assistant_route`). Adding a route means editing a 200-line function. A small route table would make each route testable alone.

Decision needed (new ADR): keep the Python server and fix the first four points, or put HAProxy in front for TLS and HTTP/2 and keep Python only for the API and the session check. HAProxy already runs as `p-observer-router`. The first option is a day of work and keeps ADR 0002 intact. The second needs a way for HAProxy to check the observer session on `/lab/` requests.

### 3.2 The page is one 1,478-line file with no tests

`observer/view.html` holds the wall, focus, picker, timeline, architecture, coverage, changes, assistant panel, and the shared-view code (`snapshot`, `pageAction`, `highlight`).

- The shared-view code decides what text leaves the workstation and which element gets clicked, and it has no test. The Python tests replace the page with a thread that posts canned answers.
- Rendering rebuilds whole panes on every 20-second refresh.
- Fix direction: split into ES modules served as static files (no build step needed), and add a small headless-browser test suite that runs in the existing capture image against a fake Splunk page. Cover `snapshot` (hidden text, raw events, password fields), click and type, and focus without reload.

### 3.3 The shared-view privacy boundary is a deny-list

`snapshot()` clones the body, removes nodes matching `NOT_FOR_MODEL` (event viewer classes, `script`, `style`, `svg`), and sends `textContent` up to 8,000 characters.

- `textContent` includes hidden elements. This is the known "hidden Splunk chrome" bug that caused a misread.
- Raw events are excluded only by CSS class. A statistics table, a dashboard table panel, or a third-party visualization that shows `_raw` or field values is not excluded.
- The terminal path (`observer.terminal read`) prints the same reading to Claude Code, which is also a hosted model. ADR 0004 only describes the API path.
- Fix direction: walk visible nodes only; treat table bodies as opt-in (send headers and row counts by default, cells on request with owner-visible evidence); record every reading as model-bound evidence for terminal runs too. Update ADR 0004.

### 3.4 Same origin means any Splunk page can drive the observer

ADR 0001 put Splunk Web on the observer's origin so pages can be framed, and ADR 0004 relies on it for DOM access. The consequence is that script running in any proxied Splunk page (a dashboard with custom JavaScript, an app under test, a stored cross-site-scripting bug) can call `/observer/api/…` with the owner's session. That includes approving a pending change, signing a view in as `lab_operator`, and saving an API key.

- This was acceptable when the observer was read-only. It matters more since #9 added approvals and the operator account.
- It cannot be fully closed while the page needs DOM access to the frame. Mitigations: require a per-page token header on state-changing API calls (raises the bar, though a hostile frame can still reach `window.parent`); require a fresh owner gesture for approvals; keep `lab_operator` sign-in off by default.
- At minimum, record this as an accepted risk in an ADR, with the condition that only trusted apps are installed in the lab.

### 3.5 Two implementations of "the page acts for the AI"

API runs keep page requests, pause state and approvals in memory inside `assistant.Run`. Terminal runs keep them in the store tables `page_requests` and `page_watch`. The server routes branch on which one applies.

- Behaviour already differs: an API run restarts lose pending requests; a terminal run times out after 15 minutes; pause is a record field in one and a table column in the other.
- Fix direction: make the store the single path for both. `Run` becomes a thin view over store rows. This also lets approvals survive a restart.

### 3.6 Run records are rewritten whole on every step

`Run.save()` serialises the full record (events plus the model message history) and replaces the row on each event. Cost grows with the square of the run length, and a crash mid-write loses nothing only because SQLite is atomic.

- Fix direction: an `events` table keyed by run and sequence, and a `messages` table. The page already asks for events after a revision.
- Check: a run that was `running` when the observer stopped stays `running` in the store, and `Assistant.start` then refuses to continue it. Mark such runs `interrupted` at startup.

### 3.7 The store writes unchanged facts every minute

In 2.6 days the store reached 70 MB: 78,000 container rows, 76,000 resource rows, 44,000 each for health, messages and web. At that rate it is about 800 MB at the 30-day limit.

- `Store.record` already detects changes for signals. Use the same test for observations: write a full row when the value changes, and otherwise update a `last_seen` time on the latest row.
- Resource use is a time series. Keep it at one-minute grain for a day and five-minute grain after.
- SQLite runs in the default rollback journal with one connection behind a global lock, and `observer.terminal` writes from a second process. Switch to WAL with a busy timeout.
- `_lab_summary` runs about 240 queries per call, per open page, every 20 seconds, and `_last_good_capture` loads 200 change rows per component with a failed capture. Keep a latest-status table or cache the summary until the next collection.

### 3.8 The observer and its lab plumbing do not survive a reboot

After the VM restart on 2026-11-09 the lab, `p-observer-router`, the nine `p-fwd-*` containers and the observer were all down until started by hand. The server runs under `nohup`.

- Add a systemd user unit for the observer (with linger), and have `lab.sh start` bring up the router.
- Login sessions are in memory, so every restart signs the owner out.
- `initial-password.txt` is still on disk. The README says to remove it once saved.

### 3.9 Polling everywhere

The page polls the lab every 20 s, the live run every 2.5 s, an open run every 1 s, and the terminal polls the store every 0.4 s. One server-sent-events stream per page for lab changes and run events would cut latency and load, and removes the "only follows a run updated within 60 s of page load" bug.

### 3.10 Previews cost more than they need to

Each 10-minute round starts a container and signs a fresh Chromium into all 19 instances. Each preview is a 1440 by 900 JPEG of about 70 KB, shown in a tile a quarter of that size.

- Keep one browser context alive between rounds, skip instances whose screen and health did not change, and store a small thumbnail next to the full image.

## 4. Design and usability findings

- **Focusing reloads the view.** Focus destroys the tile's frame and creates a new one at the launcher home; closing does it again. Expand the same frame in place with CSS. This also fixes `terminal show` landing on the launcher home.
- **Every tile opens the launcher home.** Remember the last screen per component and open that.
- **Sign-in is per instance.** "Use test account" exists only in the focused view. Offer one action that signs every live view in, and show which account each tile uses.
- **A frame has no location bar.** Show its current path, add back and reload, and make "Open in a new tab" use the current path.
- **No deep links.** The focused component, screen and tab are lost on reload. Put them in the URL fragment.
- **Screens are only searchable per component.** Add a search across all components ("open Pulse HQ overview on any HQ member").
- **The certificate state is invisible.** The page can detect an untrusted certificate indirectly (repeat static loads with a non-zero transfer size) and tell the owner that caching is off.
- **The architecture and overview tabs repeat data** from the wall with different layouts. Consider one topology view with the health badges, and drop the table.
- **The assistant panel mixes three things:** the conversation, the audit trail, and the run record. A run page with tabs (steps, evidence, verdict, versions) would read better than one scroll.

## 5. Process and repository findings

- **Merge the stack.** Four stacked PRs make every review and rebase harder. The owner has not authorised merging; ask, then merge bottom-up and close the built issues with a comment that maps each acceptance criterion to its evidence.
- **No continuous integration.** Add a workflow that runs the unit tests with and without the SDK installed.
- **README drift:** port 8765 versus the live 8766, and no mention of `signin`, `read`, `click`, `upload` or the packages folder.
- **`assistant.py` is 1,065 lines** with every tool defined as a closure inside `_tools`. Move tools into a module of plain functions that take a context object, so they can be tested without the SDK and reused by the terminal path and by scheduled checks.
- **The model id is a constant** (`claude-opus-5-5`). The brief asks for a replaceable model connection; make it a setting.

## 6. Gaps between the spec and the tickets

These user stories in #1 have no ticket or only partial coverage. Each needs a ticket before #12 to #20 can finish cleanly.

| Story | Gap |
|---|---|
| 5 | Jobs and recent configuration changes are not collected. `lab_observer` sees only its own search jobs. |
| 24 | No shared way to state an expected value from an independent search or API and compare it with what the screen shows. Every app-check ticket needs this. |
| 30, 31 | Saved, repeatable workflows and a diff before reuse. Nothing is built and no ticket exists. |
| 33, 34 | Fixtures are not named or tracked. Cleanup is free text on the approval card, and an interrupted run only lists containers still stopped. |
| 38 | Scheduled checks (#20) need checks that run without the model. Today every check is an AI run. |
| 21 | An "unverified claim" exists for coverage marks and verdicts, but ordinary answers in #7 do not mark unsupported statements. |

Suggested shape for stories 24, 30 and 38 together: a **check** is data, not a conversation. It names a component, a screen, a reading to take from that screen, an independent search or REST call, and a comparison. A walkthrough that passes can be saved as a list of checks. The scheduler runs checks without the model, and the model is only needed to write or repair them. This would be the foundation for #12 to #20 and deserves its own ADR and glossary terms ("check", "oracle", "saved workflow").

## 7. Notes on the open app-check tickets

- **#12 to #14 (Hindsight):** blocked only by #11, which is built. They need the check format above, plus lab data for the empty, unknown-version and mismatched cases. Decide whether those cases use fixtures (story 33) or a second index.
- **#15 (Spoke standalone):** `p-bravo` is the standalone Spoke. The oracle is native `/services/data/indexes` with `datatype=all`, excluding `federation_pulse` (see the lab test notes).
- **#16 (Spoke cluster):** the Alpha cluster sits behind `p-alpha-lb`. The 2026-11-10 upgrade test showed stale per-member records and the 513 default limit; both are good error and recovery cases.
- **#17, #18 (HQ):** the main lab's registry still keys Alpha to one member, so "Alpha Spoke (SHC)" shows Missing. Either approve the identity migration first or record it as a known failing case.
- **#19 (dataset trace):** needs observations at four boundaries. The observer can already read each one; what is missing is linking them into one verdict.
- **#20 (scheduled checks):** depends on the check format, not on the nine tickets it lists. Reorder the dependency.

## 8. Suggested order of work

1. Ask the owner to merge the PR stack, then close #2 to #6, #8, #10, #11 and #22 with evidence.
2. Quick server fixes from 3.1 (keep-alive, handshake off the accept loop, queue size, gzip, ETag) and focus-in-place from section 4. Measure from the Mac before and after.
3. Store changes from 3.7 and WAL, before the database grows further.
4. Unify the page-request path (3.5) and split run events into rows (3.6).
5. Fix the reading (3.3), add the browser tests (3.2), and write the accepted-risk ADR (3.4).
6. Write the ADR and tickets for checks, oracles and saved workflows (section 6).
7. Then the app checks #12 to #19, and #20 last.
8. Service unit and startup (3.8) can be done at any point; it is independent.

## 9. Rules that still apply

- Never print, commit or send the observer password, the TLS key, the Anthropic key, or the `lab_operator`, `lab_observer` or admin passwords. Pass credentials by stdin or mode-600 files, never on a command line.
- Keep credentials and raw Splunk event text out of anything sent to a hosted model.
- State-changing actions on the lab need the owner's approval and a cleanup. Do not merge pull requests without the owner's say.
- Leave the old listener on port 8765 alone.
- Mirror lab work into the observer with `observer.terminal`, record only real results, and test in the owner's view as `lab_operator`.

## 10. What was done after this review (2026-11-11)

| Finding | Done | Not done |
| --- | --- | --- |
| 3.1 web server | HTTP/1.1 keep-alive, pooled upstream connections, chunked passthrough, handshake off the accept loop, queue of 128, gzip, ETag and 304, cached lab summary. New TLS connections per Splunk page went from 55 to 85 down to 0. | Route table; replacing the server (ADR 0006 records why it stays). |
| 3.2 page tests | `tests/test_page.py` drives the page in the capture browser image. | Splitting `view.html` into files. |
| 3.3 reading | The shared view sends visible text only. | An allow-list of regions. |
| 3.4 same origin | ADR 0006 records it as an accepted risk for this lab. | |
| 3.5 two page-request paths | | Still two implementations. |
| 3.6 run records | Runs left running are marked interrupted at startup. | Events as rows. |
| 3.7 store | Unchanged observations update one row; a one-time merge took the live database from about 300,000 rows to 79,700; WAL. | |
| 3.8 startup | `python -m observer.service install` writes a systemd user service; the live observer runs from it. | Start at boot needs the owner to run `sudo loginctl enable-linger "$USER"`. |
| 3.9 polling | The lab summary is fetched conditionally. | Server-sent events. |
| 3.10 previews | | Thumbnails. |
| Section 4 usability | Focus a live tile in place, remembered screen per component, path with back and reload, deep links, one button to sign in every live view, caching-off notice. | |
| Section 6 checks | ADR 0007, glossary terms, the check engine, 19 packaged checks, the Checks tab and the six-hour schedule (#20). | Saved workflows (stories 30, 31) and fixtures (33, 34). |

First real round, 2026-11-11 16:02 UTC, run `bf18c6a8c763`: 3 passed (Hindsight, Pulse Spoke and Pulse HQ each run one version and build everywhere), 0 failed, 16 unverified. Fifteen are unverified because `lab_observer` cannot see the Pulse apps' saved searches ("Unable to find saved search"); the apps ship read-only auditor roles for this and the owner has not yet granted them. One (`hindsight-own-version-recorded`) returned no row and has not been diagnosed; Hindsight has no reader role below `power`. So #15 to #19 have their checks written and are not yet verified, and #12 is partly verified. `hq-registry-alpha-identity` is expected to fail once readable, because the registry still keys Alpha to one member's GUID.

