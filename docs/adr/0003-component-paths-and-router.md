# Give each Splunk Web its own path behind one loopback router

The wall shows every Splunk Web in the lab on the observer's single origin. All of them listen on port 8000 inside their containers, so they set identically named session and CSRF cookies (`session_id_8000`, `splunkweb_csrf_token_8000`). On one origin, signing in to one instance would replace another's session.

Each instance therefore sets Splunk's `root_endpoint` to `/lab/<container>/`, and the observer proxy rewrites cookies Splunk scopes to `/` so they are scoped to that component's path. The browser then sends each instance only its own cookies, and Splunk's own pages, assets, and redirects stay under the prefix without rewriting HTML or JavaScript. Splunk Web still answers on its published port and redirects `/` to the prefix.

Ten instances (indexers, deployers, the heavy forwarder) have no host port. Instead of recreating containers, one HAProxy container on the lab network, published on loopback only, routes `/lab/<c>/` to Splunk Web and `/mgmt/<c>/` to splunkd. The observer never exposes `/mgmt/` to the browser; it calls splunkd there as a read-only `lab_observer` account.

Many live Splunk pages would overload the owner's browser, so unselected tiles show screenshots taken by a headless browser as `lab_observer`, each stored as an observation with its capture time.
