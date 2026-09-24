#!/bin/bash
# x2rp server installer for Debian/Ubuntu. From a release:
#   curl -fsSL <release>/install.sh | sudo bash                    install or upgrade
#   curl -fsSL <release>/install.sh | sudo bash -s -- --uninstall  remove x2rp and all of its data
# From a source checkout, it installs ./x2rp-<arch> (scripts/build.sh) instead.
set -euo pipefail

# The release workflow sets this to the release the script ships in.
RELEASE_URL=@RELEASE_URL@

SERVICE=x2rp
BIN=/usr/local/bin/x2rp
UNIT=/etc/systemd/system/x2rp.service
DATA=/var/lib/x2rp
STATE="$DATA/state.json"
SYSCTL=/etc/sysctl.d/99-x2rp.conf
API=http://127.0.0.1:8800

die() { echo "ERROR: $*" >&2; exit 1; }
# Under `curl | bash` stdin is this script, so every answer comes from the terminal.
ask() { read -r "$@" </dev/tty; }
confirm() { ask -p "$1 [y/N] " -n 1; echo; [[ $REPLY =~ ^[Yy]$ ]]; }

stop_service() {
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
}

# The token goes to curl on stdin, so it never shows in the process list.
cf_zone_ok() {
    printf 'Authorization: Bearer %s\n' "$1" |
        curl -fsS -G -H @- --data-urlencode "name=$2" \
            https://api.cloudflare.com/client/v4/zones 2>/dev/null |
        jq -e '.success and (.result | length > 0)' >/dev/null
}

# Everything runs from here, so a download cut short executes nothing.
main() {
    [[ $EUID -eq 0 ]] || die "run as root"

    MODE=install
    case "${1:-}" in
        "") ;;
        --uninstall) MODE=uninstall ;;
        *) die "unknown option $1 (see the header of this script)" ;;
    esac

    if [[ $MODE == uninstall ]]; then
        [[ -f $UNIT || -f $BIN || -d $DATA ]] || { echo "$SERVICE is not installed"; exit 0; }
        confirm "Remove $SERVICE, its state and its certificates?" || exit 0
        stop_service
        rm -rf "$UNIT" "$BIN" "$DATA" "$SYSCTL"
        systemctl daemon-reload
        if id -u "$SERVICE" >/dev/null 2>&1; then userdel "$SERVICE"; fi
        echo "$SERVICE removed"
        exit 0
    fi

    command -v apt-get >/dev/null || die "this installer supports Debian/Ubuntu only"
    case "$(uname -m)" in
        x86_64|amd64) ARCH=x86_64 ;;
        aarch64|arm64) ARCH=aarch64 ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac

    for dep in curl jq; do
        command -v "$dep" >/dev/null || { apt-get update -qq && apt-get install -y -qq curl jq; break; }
    done

    SRC=./x2rp-$ARCH
    if [[ ! -f $SRC ]]; then
        [[ $RELEASE_URL == https://* ]] || die "$SRC not found (build it with scripts/build.sh server)"
        SRC=$(mktemp)
        trap 'rm -f "$SRC"' EXIT
        echo "Downloading x2rp-$ARCH from $RELEASE_URL"
        curl -fsSL -o "$SRC" "$RELEASE_URL/x2rp-$ARCH"
    fi

    if jq -e '.initialized == true' "$STATE" >/dev/null 2>&1; then
        DOMAIN=$(jq -r .domain "$STATE")
        echo "Upgrading the existing install for $DOMAIN"
        SETUP=false
    else
        { : </dev/tty; } 2>/dev/null || die "first-time setup needs an interactive terminal"
        ask -p "Domain (e.g. example.com): " DOMAIN
        [[ -n $DOMAIN ]] || die "a domain is required"
        while true; do
            ask -sp "Admin password (12-128 characters): " ADMIN_PASSWORD; echo
            ask -sp "Confirm admin password: " PASSWORD_AGAIN; echo
            if [[ $ADMIN_PASSWORD != "$PASSWORD_AGAIN" ]]; then
                echo "Passwords do not match"
            elif (( ${#ADMIN_PASSWORD} < 12 || ${#ADMIN_PASSWORD} > 128 )); then
                echo "Password must be 12-128 characters"
            else
                break
            fi
        done
        unset PASSWORD_AGAIN
        echo "Cloudflare API token with Zone → DNS → Edit on $DOMAIN (for wildcard TLS)"
        while true; do
            ask -sp "Cloudflare API token: " CF_API_TOKEN; echo
            [[ -n $CF_API_TOKEN ]] && cf_zone_ok "$CF_API_TOKEN" "$DOMAIN" && break
            echo "Token rejected, or it cannot see a Cloudflare zone named $DOMAIN"
        done
        SETUP=true
    fi

    stop_service
    if command -v ss >/dev/null; then
        for port in 80 443 8800; do
            listener=$(ss -Hltnp "sport = :$port")
            [[ -z $listener ]] || die "TCP $port is already in use: $listener"
        done
    fi

    # Larger socket buffers keep QUIC from dropping under load; BBR where the kernel has it.
    mkdir -p "${SYSCTL%/*}"
    {
        echo "net.core.rmem_max = 4194304"
        echo "net.core.wmem_max = 4194304"
        if modprobe tcp_bbr 2>/dev/null; then
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        fi
    } > "$SYSCTL"
    sysctl -p "$SYSCTL" >/dev/null || true

    install -m 0755 "$SRC" "$BIN"
    id -u "$SERVICE" >/dev/null 2>&1 ||
        useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$SERVICE"
    install -d -m 0700 -o "$SERVICE" -g "$SERVICE" "$DATA"

    # main.rs sizes its shutdown grace to TimeoutStopSec=15.
    cat > "$UNIT" <<UNIT
[Unit]
Description=x2rp reverse proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=$BIN run
Restart=always
RestartSec=10
User=$SERVICE
Group=$SERVICE
TimeoutStopSec=15
KillMode=mixed
KillSignal=SIGTERM
LimitNOFILE=65535
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$DATA
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now "$SERVICE"

    tries=0
    until curl -fsS "$API/login.html" >/dev/null 2>&1; do
        (( ++tries < 30 )) || die "$SERVICE did not answer on $API; see: journalctl -u $SERVICE"
        sleep 1
    done

    if [[ $SETUP == true ]]; then
        code=$(jq -n --arg domain "$DOMAIN" --arg admin_password "$ADMIN_PASSWORD" \
                --arg cf_api_token "$CF_API_TOKEN" '{$domain, $admin_password, $cf_api_token}' |
            curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/api/setup" \
                -H 'Content-Type: application/json' --data-binary @-) || true
        unset ADMIN_PASSWORD CF_API_TOKEN
        case $code in
            # The proxy only starts if the state is initialised at boot.
            200) systemctl restart "$SERVICE" ;;
            409) echo "Already set up; keeping the existing configuration" ;;
            *) die "setup failed (HTTP $code); see: journalctl -u $SERVICE" ;;
        esac
    fi

    echo "$SERVICE is running. Admin console: https://x2rp.$DOMAIN"
    echo "*.$DOMAIN must resolve to this server. Follow certificate issuance with: x2rp logs"
}

main "$@"
