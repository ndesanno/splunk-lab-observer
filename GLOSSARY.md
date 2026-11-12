# Splunk Lab Observer

Terms for describing what the lab owner sees and what an AI can verify.

## Language

**Lab component**:
A deployed part of the lab that can be observed independently, such as a Splunk search head, indexer, manager, application, container, or host.

**Screen**:
A navigable page or workflow within a component's user interface.

**Component view**:
The owner's direct view of a lab component at a point in time. It may show a real web screen or a console and telemetry view for a component without a web interface.

**Preview**:
A screenshot of a component view taken by the observer at a recorded time. A preview stands in for a live view and always shows its capture time.

**Owner label**:
A name or description the lab owner gave a component. It is shown instead of the discovered name but never replaces a discovered fact.

**Observation**:
A timestamped fact collected directly from a component, such as its status, a search result, a log entry, or a captured view.

**Evidence**:
One or more observations used to support or challenge a conclusion about lab behavior.

**Claim**:
An AI statement about lab behavior that points to the evidence and time on which it is based.

**Run**:
A bounded guided walkthrough, test, or investigation with recorded steps, observations, and an outcome.

**Fixture**:
Disposable lab data or configuration created to exercise behavior during a test run.

**Approval**:
The owner's decision on one state-changing step an AI asks to take, shown with its reason, expected effect, and cleanup. Without it the step does not run.

**Model-bound evidence**:
The exact text a tool returned to the hosted AI model during a run, kept with the step so the owner can see everything that left the workstation.

**Coverage mark**:
The recorded status of one case (normal, empty, incorrect, permission, error, recovery) of one app feature or screen. It counts as tested only with a pass or fail verdict and the run steps that show it.

**Check**:
A stored comparison between what an app shows and an independent reading of the same fact, run by the observer with the read-only account and without an AI model. Its result is pass, fail or unverified.

**Reading**:
One value taken for a check: a search result, a value a page shows, an installed version, a container image tag, or a fixed value an app rule requires. Each reading is a step of the round's run.

**Page reading**:
A reading of what a Splunk Web page shows to the read-only account in a headless browser, taken once the page's searches have settled.

**Known failure**:
A failing check the owner has accepted with a reason. It keeps its fail result and coverage mark but no longer fails the round. The acceptance ends when the check's finding changes.

**Independent reading**:
The reading a check compares against. It comes from Splunk itself and never passes through the app under test.

**Round**:
One run of every check, or of the checks the owner picked. It is kept as a run with origin `check`.
