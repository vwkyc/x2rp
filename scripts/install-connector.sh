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
SYSCTL=/etc/sysctl.d/90-$NAME.conf

die() { echo "error: $*" >&2; exit 1; }
# Under `curl | bash` stdin is this script, so answers come from the terminal.
confirm() { read -rp "$1 [y/N] " -n 1 -r </dev/tty; echo; [[ $REPLY =~ ^[Yy]$ ]]; }

verify_release_sha256() {
    local file="$1" name="$2" sums expected
    sums=$(curl -fsSL "$RELEASE_URL/SHA256SUMS") || die "failed to download SHA256SUMS"
    expected=$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1; exit }' <<< "$sums")
    [[ $expected =~ ^[0-9a-fA-F]{64}$ ]] || die "no SHA256 entry for $name in SHA256SUMS"
    printf '%s  %s\n' "$expected" "$file" | sha256sum -c --status - || die "SHA256 checksum mismatch for $name"
}

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
            --server) [[ $# -ge 2 ]] || die "--server requires a value"; SERVER="$2"; shift 2 ;;
            --token) [[ $# -ge 2 ]] || die "--token requires a value"; TOKEN="$2"; shift 2 ;;
            --uninstall) MODE=uninstall; shift ;;
            *) die "unknown option $1 (see the header of this script)" ;;
        esac
    done

    # An https origin only: no path, query, fragment, whitespace, or userinfo.
    origin_re='^https://[][A-Za-z0-9.:-]+$'

    if [[ $MODE == uninstall ]]; then
        [[ -f $UNIT || -f $BIN ]] || { echo "$NAME is not installed"; exit 0; }
        confirm "Remove $NAME?" || exit 0
        # Tell the server first so the admin console shows it offline right away.
        # Validate values from the service-owned config before invoking curl as root.
        if [[ -f $CONF ]] && command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
            SERVER_NOTIFY=$(jq -r '.server // empty' "$CONF" 2>/dev/null || true)
            SERVER_NOTIFY="${SERVER_NOTIFY%/}"
            TOKEN_NOTIFY=$(jq -r '.token // empty' "$CONF" 2>/dev/null || true)
            if [[ $SERVER_NOTIFY =~ $origin_re && $TOKEN_NOTIFY =~ ^[[:graph:]]+$ ]]; then
                # The token goes to curl on stdin, so it never shows in the process list.
                curl -fsS -m 5 --proto '=https' -X POST -H @- -- \
                    "${SERVER_NOTIFY}/api/connector/disconnect" \
                    <<<"Authorization: Bearer ${TOKEN_NOTIFY}" >/dev/null 2>&1 || true
            fi
            unset TOKEN_NOTIFY SERVER_NOTIFY
        fi
        stop_service
        rm -rf "$UNIT" "$BIN" "$CONF_DIR" "$SYSCTL"
        systemctl daemon-reload
        if id -u "$NAME" >/dev/null 2>&1; then userdel "$NAME"; fi
        echo "$NAME removed"
        exit 0
    fi

    SERVER="${SERVER%/}"
    if [[ -z $SERVER && -z $TOKEN ]]; then
        [[ -f $CONF ]] || die "--server and --token are required"
        echo "Upgrading $NAME, keeping $CONF"
    else
        [[ -n $SERVER && -n $TOKEN ]] || die "--server and --token are required"
        [[ $SERVER =~ $origin_re ]] || die "--server must look like https://x2rp.example.com"
        [[ ! -f $UNIT ]] || confirm "Replace the installed $NAME?" || exit 1
    fi

    case "$(uname -m)" in
        x86_64|amd64) ARCH=x86_64 ;;
        aarch64|arm64) ARCH=aarch64 ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac

    for dep in curl jq; do
        if ! command -v "$dep" >/dev/null; then
            command -v apt-get >/dev/null || die "$dep is required; install curl and jq and re-run"
            apt-get update -qq && apt-get install -y -qq curl jq
            break
        fi
    done

    SRC=./$NAME-$ARCH
    if [[ ! -f $SRC ]]; then
        [[ $RELEASE_URL == https://* ]] || die "$SRC not found (build it with scripts/build.sh connector)"
        SRC=$(mktemp)
        trap 'rm -f "$SRC"' EXIT
        echo "Downloading $NAME-$ARCH from $RELEASE_URL"
        curl -fsSL -o "$SRC" "$RELEASE_URL/$NAME-$ARCH"
        verify_release_sha256 "$SRC" "$NAME-$ARCH"
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
        useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$NAME"
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
