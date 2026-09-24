#!/bin/bash
# x2rp connector installer for systemd hosts. The admin console's Add connector
# dialog gives the exact command. From a release:
#   curl -fsSL <release>/install-connector.sh | sudo bash -s -- --server https://x2rp.example.com --token TOKEN
#   curl -fsSL <release>/install-connector.sh | sudo bash                  # upgrade, keeping the config
#   curl -fsSL <release>/install-connector.sh | sudo bash -s -- --uninstall
# From a source checkout, it installs ./x2rp-connector-<arch> (scripts/build.sh) instead.
set -euo pipefail

# The release workflow sets this to the release the script ships in.
RELEASE_URL=@RELEASE_URL@

NAME=x2rp-connector
BIN=/usr/local/bin/$NAME
UNIT=/etc/systemd/system/$NAME.service
CONF_DIR=/etc/$NAME
CONF=$CONF_DIR/config.json
HOME_DIR=/var/lib/$NAME
SYSCTL=/etc/sysctl.d/90-$NAME.conf

die() { echo "error: $*" >&2; exit 1; }
# Under `curl | bash` stdin is this script, so answers come from the terminal.
confirm() { read -rp "$1 [y/N] " -n 1 -r </dev/tty; echo; [[ $REPLY =~ ^[Yy]$ ]]; }

stop_service() {
    systemctl disable --now "$NAME" >/dev/null 2>&1 || true
    systemctl reset-failed "$NAME" >/dev/null 2>&1 || true
}

# Everything runs from here, so a download cut short executes nothing.
main() {
    [[ $EUID -eq 0 ]] || die "run as root"

    SERVER="" TOKEN="" MODE=install
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --server) SERVER="${2:-}"; shift 2 ;;
            --token) TOKEN="${2:-}"; shift 2 ;;
            --uninstall) MODE=uninstall; shift ;;
            *) die "unknown option $1 (see the header of this script)" ;;
        esac
    done

    if [[ $MODE == uninstall ]]; then
        [[ -f $UNIT || -f $BIN ]] || { echo "$NAME is not installed"; exit 0; }
        confirm "Remove $NAME?" || exit 0
        # Tell the server first so the admin console shows it offline right away.
        if [[ -f $CONF ]] && command -v jq >/dev/null; then
            curl -fsS -m 5 -X POST "$(jq -r .server "$CONF")/api/connector/disconnect" \
                -H "Authorization: Bearer $(jq -r .token "$CONF")" >/dev/null 2>&1 || true
        fi
        stop_service
        rm -rf "$UNIT" "$BIN" "$CONF_DIR" "$HOME_DIR" "$SYSCTL"
        systemctl daemon-reload
        id -u "$NAME" >/dev/null 2>&1 && userdel "$NAME" || true
        echo "$NAME removed"
        exit 0
    fi

    SERVER="${SERVER%/}"
    if [[ -z $SERVER && -z $TOKEN ]]; then
        [[ -f $CONF ]] || die "--server and --token are required"
        echo "Upgrading $NAME, keeping $CONF"
    else
        [[ -n $SERVER && -n $TOKEN ]] || die "--server and --token are required"
        # An https origin only: no path, query, fragment or userinfo.
        origin_re='^https://[][A-Za-z0-9.:-]+$'
        [[ $SERVER =~ $origin_re ]] || die "--server must look like https://x2rp.example.com"
        [[ ! -f $UNIT ]] || confirm "Replace the installed $NAME?" || exit 1
    fi

    case "$(uname -m)" in
        x86_64|amd64) ARCH=x86_64 ;;
        aarch64|arm64) ARCH=aarch64 ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac

    for dep in curl jq; do
        command -v "$dep" >/dev/null || { apt-get update -qq && apt-get install -y -qq curl jq; break; }
    done

    SRC=./$NAME-$ARCH
    if [[ ! -f $SRC ]]; then
        [[ $RELEASE_URL == https://* ]] || die "$SRC not found (build it with scripts/build.sh connector)"
        SRC=$(mktemp)
        trap 'rm -f "$SRC"' EXIT
        echo "Downloading $NAME-$ARCH from $RELEASE_URL"
        curl -fsSL -o "$SRC" "$RELEASE_URL/$NAME-$ARCH"
    fi

    stop_service

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
    id -u "$NAME" >/dev/null 2>&1 ||
        useradd --system --home-dir "$HOME_DIR" --create-home --shell /usr/sbin/nologin "$NAME"
    if [[ -n $TOKEN ]]; then
        install -d -m 0750 -o root -g "$NAME" "$CONF_DIR"
        ( umask 077; jq -n --arg server "$SERVER" --arg token "$TOKEN" '{$server, $token}' > "$CONF" )
        chown "$NAME:$NAME" "$CONF"
        chmod 0640 "$CONF"
        unset TOKEN
    fi

    cat > "$UNIT" <<UNIT
[Unit]
Description=x2rp connector
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=$BIN run
Restart=on-failure
RestartSec=5
User=$NAME
Group=$NAME
LimitNOFILE=65535
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now "$NAME"
    echo "$NAME installed; check it with: $NAME status"
}

main "$@"
