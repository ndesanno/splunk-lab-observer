# Serve the first Splunk component view through a local same-origin proxy

Splunk's web responses use `X-Frame-Options: SAMEORIGIN`, so a page on the observer's port cannot embed a direct view from a different Splunk port. The first component view serves the observer page and proxies one loopback Splunk web endpoint under the same browser origin. This preserves the real Splunk interface and its login flow while letting the owner watch it inside the observer.

The proxy binds to loopback, accepts only a loopback upstream, rejects foreign browser origins for state-changing requests, and does not log request contents. A later multi-component view wall must give each component a safe same-origin route or a similarly direct view without weakening these boundaries.
