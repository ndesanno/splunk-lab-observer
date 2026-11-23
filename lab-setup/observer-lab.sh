#!/usr/bin/env bash
# Prepare a podman-based Splunk lab for Splunk Lab Observer.
#
#   ./observer-lab.sh web       give each Splunk Web its own path, /lab/<container>, so one browser origin
#                               can show them all without their session cookies colliding (restart needed)
#   ./observer-lab.sh router    an HAProxy container on 127.0.0.1:$ROUTER_PORT that routes /lab/<container>/
#                               to that container's Splunk Web and /mgmt/<container>/ to its splunkd
#   ./observer-lab.sh account   read-only lab_observer role and user on every instance; the password is
#                               generated once and written only to $CONFIG_DIR/splunk.json (mode 600)
#   ./observer-lab.sh operator  optional lab_operator user (admin role) for changes you approve in the
#                               observer; password only in $CONFIG_DIR/operator.json (mode 600)
#   ./observer-lab.sh status    every Splunk Web and lab_observer login through the router
#
# Settings (environment variables):
#   LAB_NETWORK          podman network the lab containers share (required)
#   SPLUNK_CONTAINERS    space-separated Splunk Enterprise container names; default: every running
#                        container on LAB_NETWORK whose image is splunk/splunk
#   SPLUNK_ADMIN_USER    admin account on every instance (default admin)
#   SPLUNK_ADMIN_PASSWORD  its password; prompted for when unset (never passed on a command line)
#   ROUTER_NAME          router container name (default observer-router)
#   ROUTER_PORT          loopback port for the router (default 8190)
#   HAPROXY_IMAGE        router image (default docker.io/library/haproxy:2.8.31-alpine)
#   CONFIG_DIR           observer config directory (default ~/.config/splunk-lab-observer)
#
# Each container must serve Splunk Web on port 8000 and splunkd on 8089, and have curl (the official
# splunk/splunk image does). Container names become the observer's component ids.
set -euo pipefail

: "${LAB_NETWORK:?Set LAB_NETWORK to the podman network your Splunk containers share}"
SPLUNK_ADMIN_USER=${SPLUNK_ADMIN_USER:-admin}
ROUTER_NAME=${ROUTER_NAME:-observer-router}
ROUTER_PORT=${ROUTER_PORT:-8190}
HAPROXY_IMAGE=${HAPROXY_IMAGE:-docker.io/library/haproxy:2.8.31-alpine}
CONFIG_DIR=${CONFIG_DIR:-$HOME/.config/splunk-lab-observer}
SPLUNK_HOME_IN_CONTAINER=${SPLUNK_HOME_IN_CONTAINER:-/opt/splunk}
OBSERVER_USER=lab_observer
OPERATOR_USER=lab_operator
# Read-only: what discovery and health need, nothing that edits or reveals secrets.
OBSERVER_CAPS=(list_health list_indexer_cluster list_search_head_clustering list_introspection list_settings
    list_deployment_server list_deployment_client list_forwarders list_dist_peer list_inputs list_search_scheduler)

instances() {
    if [[ -n ${SPLUNK_CONTAINERS:-} ]]; then
        tr ' ' '\n' <<<"$SPLUNK_CONTAINERS" | grep -v '^$'
    else
        podman ps --filter "network=$LAB_NETWORK" --format '{{.Names}} {{.Image}}' | awk '$2 ~ /splunk\/splunk/ {print $1}'
    fi
}

admin_password() {
    if [[ -z ${SPLUNK_ADMIN_PASSWORD:-} ]]; then
        read -r -s -p "Password for $SPLUNK_ADMIN_USER on the lab instances: " SPLUNK_ADMIN_PASSWORD; echo >&2
    fi
}

# splunkd REST inside a container. Credentials reach curl through its config on stdin, never argv;
# EXTRA adds more curl config lines (for example a password form field).
api() {
    local c=$1; shift
    { printf 'user = "%s:%s"\n' "$SPLUNK_ADMIN_USER" "$SPLUNK_ADMIN_PASSWORD"
      if [[ -n ${EXTRA:-} ]]; then printf '%s\n' "$EXTRA"; fi
    } | podman exec -i "$c" curl -sk -fS -K - "$@"
}

# A random password, created once and kept in a mode-600 JSON file with the router address.
stored_password() {
    local file=$1 user=$2
    if [[ -f $file ]]; then
        python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$file"
        return
    fi
    local pw
    pw=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"
    ( umask 077; printf '{"username": "%s", "password": "%s", "router": "http://127.0.0.1:%s", "network": "%s"}\n' \
        "$user" "$pw" "$ROUTER_PORT" "$LAB_NETWORK" >"$file" )
    printf '%s\n' "$pw"
}

cmd_web() {
    local c changed=()
    for c in $(instances); do
        local conf=$SPLUNK_HOME_IN_CONTAINER/etc/system/local/web.conf
        if podman exec -u splunk "$c" grep -q '^root_endpoint' "$conf" 2>/dev/null; then
            echo "$c: $(podman exec -u splunk "$c" grep '^root_endpoint' "$conf")"
            continue
        fi
        podman exec -u splunk "$c" sh -c "f=$conf; touch \$f
            if grep -q '^\[settings\]' \$f; then sed -i '0,/^\[settings\]/s//[settings]\nroot_endpoint = \/lab\/$c/' \$f
            else printf '\n[settings]\nroot_endpoint = /lab/$c\n' >> \$f; fi"
        echo "$c: root_endpoint = /lab/$c"
        changed+=("$c")
    done
    if [[ ${#changed[@]} -gt 0 ]]; then
        echo "Splunk Web reads root_endpoint at start. Restart these instances the way your lab expects"
        echo "(cluster managers before peers, one search head cluster member at a time): ${changed[*]}"
    fi
}

router_cfg() {
    cat <<EOF
global
    maxconn 2000
defaults
    mode http
    timeout connect 5s
    timeout client 300s
    timeout server 300s
resolvers podman
    parse-resolv-conf
    hold valid 10s
frontend observer
    bind :$ROUTER_PORT
    use_backend web_%[path,field(3,/)] if { path_beg /lab/ }
    use_backend mgmt_%[path,field(3,/)] if { path_beg /mgmt/ }
    default_backend unknown
backend unknown
    http-request return status 404 content-type text/plain string "unknown component"
EOF
    local c
    for c in $(instances); do
        printf 'backend web_%s\n    server s %s:8000 resolvers podman init-addr last,libc,none\n' "$c" "$c"
        printf 'backend mgmt_%s\n    http-request replace-path /mgmt/[^/]+(/.*) \\1\n' "$c"
        printf '    server s %s:8089 ssl verify none resolvers podman init-addr last,libc,none\n' "$c"
    done
}

cmd_router() {
    local dir=$CONFIG_DIR/router
    mkdir -p "$dir"
    router_cfg >"$dir/haproxy.cfg"
    podman rm -f -t 5 "$ROUTER_NAME" >/dev/null 2>&1 || true
    # Loopback only: the observer is the one client, and splunkd is reachable through it.
    podman run -d --name "$ROUTER_NAME" --hostname "$ROUTER_NAME" --network "$LAB_NETWORK" --memory=64m \
        -p "127.0.0.1:$ROUTER_PORT:$ROUTER_PORT" \
        -v "$dir/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro,Z" "$HAPROXY_IMAGE" >/dev/null
    sleep 2
    podman ps --filter name="^$ROUTER_NAME\$" --format '{{.Names}} {{.Status}} {{.Ports}}'
}

# Create or update one role and one user on every instance (search head cluster members accept the
# update when the role or user has already replicated to them).
ensure_user() {
    local user=$1 role=$2 pw=$3 caps=$4 c
    for c in $(instances); do
        if [[ -n $caps ]]; then
            if api "$c" "https://localhost:8089/services/authorization/roles/$role" -o /dev/null 2>/dev/null; then
                EXTRA="$caps" api "$c" "https://localhost:8089/services/authorization/roles/$role" -d imported_roles=user -o /dev/null
            else
                EXTRA="$caps" api "$c" https://localhost:8089/services/authorization/roles -d "name=$role" -d imported_roles=user -o /dev/null
            fi
        fi
        if api "$c" "https://localhost:8089/services/authentication/users/$user" -o /dev/null 2>/dev/null; then
            EXTRA="data-urlencode = \"password=$pw\"" api "$c" "https://localhost:8089/services/authentication/users/$user" \
                -d "roles=$role" -o /dev/null
        else
            EXTRA="data-urlencode = \"password=$pw\"" api "$c" https://localhost:8089/services/authentication/users \
                -d "name=$user" -d "roles=$role" -d force-change-pass=0 -o /dev/null
        fi
        echo "$c: $user ready"
    done
}

cmd_account() {
    admin_password
    local pw caps="" cap
    pw=$(stored_password "$CONFIG_DIR/splunk.json" "$OBSERVER_USER")
    for cap in "${OBSERVER_CAPS[@]}"; do caps+="data = \"capabilities=$cap\""$'\n'; done
    ensure_user "$OBSERVER_USER" "$OBSERVER_USER" "$pw" "$caps"
}

cmd_operator() {
    admin_password
    local pw
    pw=$(stored_password "$CONFIG_DIR/operator.json" "$OPERATOR_USER")
    ensure_user "$OPERATOR_USER" admin "$pw" ""
}

cmd_status() {
    local c
    podman ps -a --filter name="^$ROUTER_NAME\$" --format '{{.Names}} {{.Status}} {{.Ports}}'
    for c in $(instances); do
        printf '%-24s web %s  %s login %s\n' "$c" \
            "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ROUTER_PORT/lab/$c/en-US/account/login")" \
            "$OBSERVER_USER" \
            "$(python3 - "$c" "$CONFIG_DIR/splunk.json" "$ROUTER_PORT" <<'EOF'
import base64, json, sys, urllib.request
component, config, port = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    cfg = json.load(open(config))
except OSError:
    print("no account yet (run: account)"); sys.exit()
req = urllib.request.Request(f"http://127.0.0.1:{port}/mgmt/{component}/services/authentication/current-context?output_mode=json")
req.add_header("Authorization", "Basic " + base64.b64encode(f"{cfg['username']}:{cfg['password']}".encode()).decode())
try:
    print(json.load(urllib.request.urlopen(req, timeout=10))["entry"][0]["content"]["username"])
except Exception as e:
    print(f"failed ({e.__class__.__name__})")
EOF
)"
    done
}

case ${1:-} in
    web) cmd_web ;;
    router) cmd_router ;;
    account) cmd_account ;;
    operator) cmd_operator ;;
    status) cmd_status ;;
    *) sed -n '2,25p' "$0"; exit 2 ;;
esac
