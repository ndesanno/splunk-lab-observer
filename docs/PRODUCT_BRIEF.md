# Product brief

## Purpose

Give the lab owner one local web interface for observing every deployed lab component, inspecting the screens and evidence directly, and asking an AI to explain, guide, test, diagnose, and eventually operate the lab.

The owner must be able to verify an AI claim against a visible component view, search result, or log entry. AI summaries are useful navigation and interpretation, not the sole account of lab state.

## First milestone

- Support Hindsight, Federation Pulse HQ, and Federation Pulse Spoke. Inventory their features and screens, and show which behaviors have been verified.
- Show a lab overview with discovered components, topology, health, recent changes and errors, active jobs, resource use, freshness, and history.
- Provide a selectable wall of component views. Web components show their real interface; headless components show a live console and telemetry view. The owner can select and rearrange views, save a layout, expand one view, and navigate known app screens and workflows.
- Keep selected views live. Other views may use visibly timestamped previews when necessary to keep the interface responsive. A synchronized timeline shows saved views and observations from a chosen moment.
- Offer two AI modes: a guided walkthrough that pauses for the owner, and an agreed test workflow that can proceed while the owner watches. The owner can pause, stop, or take over at any time. AI clicks and inputs appear in the same view, with a timestamped action trail.
- Test both UI behavior and displayed information. Use app rules and independent Splunk searches or APIs as expected results. Mark a check unverified when evidence is missing. Include normal use, empty and incorrect data, permissions, error states, and recovery in the per-feature coverage record.
- Verify Federation Pulse HQ and Spoke separately and follow a dataset from Spoke publication through HQ display. Cover standalone and search head cluster deployments actually present in the lab; label untested topologies clearly.
- Identify the local source revision and installed app version before explaining or testing an app, and surface mismatches.
- Save each run's steps, screenshots, relevant searches and logs, failures, verdict, lab state, and app versions. Retain runs for 30 days by default and allow pinning. AI claims link to the exact evidence and time that support them.

## Operation and control

- Run locally for the owner first. Discover components and relationships automatically while allowing corrected names and descriptions; show provenance and last-check time.
- Collect lightweight health and change signals in the background. Run detailed checks on demand. Schedule safe, read-only smoke checks once repeatable.
- Let the AI use an audited tool layer for browser actions, Splunk searches and APIs, and lab host commands. Use dedicated accounts with task-appropriate access and credentials outside the repository. Show the account used for each run.
- Let the AI investigate freely. Before a state-changing test or operational action, show a specific plan, expected effects, and cleanup steps for approval. Record changes, attempt planned cleanup after failure, and show unresolved changes.
- Permit clearly named, disposable test fixtures under an approved test plan.
- Allow a hosted AI model to receive lab metadata and test results while keeping credentials and raw event contents local. Show the evidence being sent. Keep the model connection replaceable.
- Keep ordinary browsing out of test records. Record the owner's actions when participating in a guided walkthrough or test.

## Growth path

After the first milestone, expand from diagnosis, walkthroughs, and tests to approved deployment, configuration, restart, and repair workflows. Keep app-level logic and data correctness tests with each app's source; keep lab-wide browser and cross-app workflows here, with linked results in this interface. Start with in-app status and history; add external notifications after their signal quality is established.
