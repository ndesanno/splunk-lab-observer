# Checks are data, compared against an independent reading, and run without a model

The app tickets (#12 to #19) each ask whether what an app shows is true, and #20 asks for that to be re-asked on a schedule. A conversation with Claude can answer the question once, but it costs a model call each time, its steps vary between runs, and a scheduled run has nobody present to approve anything. So a check is a small piece of data, not a conversation. It names what the app shows (a reading), an independent reading of the same fact, and how to compare them:

- A reading is one search as the read-only `lab_observer` account, the installed version and build of an app on every component, or a fixed value that an app rule requires.
- The independent reading must not pass through the app under test. For Pulse it is Splunk's own index list, server GUID and member list; for Hindsight it is `server/info`. A check that compares an app's output with another view of the same app's output proves nothing and is not written.
- A reading can also be the version tag of the image a container runs, which is how a forwarder's recorded version is checked without asking the forwarder. A search can be run once per named host, so one check covers every server.
- The comparison is `equal`, `each_equal` (value by value, host by host) or `all_equal` (every member shows the same value).
- Several checks can stand for the same coverage case. The case takes the worst of their latest results, so a pass never hides a failure.

Checks ship as JSON under `observer/checks/` and the owner can add more in `checks.json` in the config directory. They are validated when loaded; a search that uses a command that writes or runs something (`outputlookup`, `collect`, `delete`, `sendalert`, `map` and the like) is refused and reported, and the account could not write in any case.

A round runs every check as one run with origin `check` and no model. Each reading is a step that keeps the search, the component, the account and the value taken. Each result names the steps it rests on, and marks the coverage case the check stands for, by "scheduled check". The round's verdict is fail if any check failed, inconclusive if any could not be verified, and pass otherwise. The scheduler starts a round ten minutes after the observer starts and then every six hours; the owner can run one check or all of them from the Checks tab.

**A reading that cannot be taken makes the check unverified, never passed.** Missing permission, an unreachable component, an empty answer and a missing field all end the same way, with the reason shown. This is the rule that keeps a green board honest, and it is why a lab where `lab_observer` cannot see an app's saved searches shows most checks as unverified until the owner grants the app's read-only role.

What this does not do: a check reads splunkd, not the rendered page. Whether a dashboard draws the number its search returns is still a walkthrough in the owner's view. Checks cover the cases the lab is in now (normal, and whatever is really wrong); the empty, incorrect, permission, error and recovery cases need the lab to be put into that state, which is a change and so needs the owner. Turning a passed walkthrough into checks (saved workflows, stories 30 and 31) is left for later, and the check format is meant to be its target.

## Addendum (2026-11-11): page readings and accepted failures

Two search readings can agree while the dashboard shows something else, so a reading may now be a
page: the capture container's headless browser, signed in as the read-only account, opens the page
and takes values from its visible text. A dashboard shows placeholder values while its searches run;
a value counts only after it has been the same for three reads and the page has made no search
request for four seconds. A page that does not settle is unverified. All pages of a round are read
by one browser, before the comparisons.

A failure the owner knows about can be accepted with a reason. The result and the coverage mark stay
"fail"; only the round's verdict and the new-failure notice leave it out. Acceptance is tied to the
finding's exact text and ends when that changes, so an accepted failure cannot hide a different one.

