# Issue tracker: GitHub

Specs and tickets for this project live in GitHub Issues in `ndesanno/splunk-lab-observer`. This repository is private. Use `gh` from this checkout, and verify the target with `gh repo view --json nameWithOwner` before the first issue write in a session.

## Operations

- Create: `gh issue create --title "..." --body-file <file> --label ready-for-agent`.
- Read: `gh issue view <number> --json number,title,body,labels,comments`.
- List: `gh issue list --state open --json number,title,body,labels`.
- Edit labels: `gh issue edit <number> --add-label <label>` or `--remove-label <label>`.
- Comment: `gh issue comment <number> --body-file <file>`.
- Close: explain the outcome in a comment, then `gh issue close <number>`.

For a ticket blocked by another issue, use GitHub's native issue dependency when available. Otherwise, include `Blocked by: #<number>` in its body. A ticket is ready when every blocker is closed.

Pull requests are not a triage request surface for this project.

When a skill says to publish a spec or ticket, create an issue here. Keep credentials, raw lab events, and sensitive screenshots out of issue bodies.
