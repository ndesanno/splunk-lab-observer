# Splunk Lab Observer

Terms for describing what the lab owner sees and what an AI can verify.

## Language

**Lab component**:
A deployed part of the lab that can be observed independently, such as a Splunk search head, indexer, manager, application, container, or host.

**Screen**:
A navigable page or workflow within a component's user interface.

**Component view**:
The owner's direct view of a lab component at a point in time. It may show a real web screen or a console and telemetry view for a component without a web interface.

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
