# X2RP - Rust Reverse Proxy

x2rp publishes HTTP services under subdomains of your domain with automatic
wildcard TLS. It can reach services on the host it runs on, or services on
private networks through an outbound connector. You don't need to open any
ports on the private side.

- **Edge proxy** built on [Pingora](https://github.com/cloudflare/pingora). It
  terminates TLS on `:443` and redirects `:80` to HTTPS.
- **Wildcard certificates** from Let's Encrypt via ACME DNS-01 on Cloudflare,
  renewed automatically.
- **Connectors** dial out to the server over QUIC (UDP 443) and fall back to
  WebSocket over TLS (TCP 443) when UDP is blocked.
- **Per-route access control**: an optional allowlist of client IPs and CIDR
  blocks.
- **Rate limiting** per client, where IPv6 clients are grouped by /64. The
  login endpoint has its own stricter tier.
- **Admin console** at `https://x2rp.<domain>`, protected by an Argon2id
  password, `__Host-` session cookies and CSRF tokens bound to the session.

## Requirements

- A Linux server with a public IP. TCP 443 and UDP 443 must be reachable.
- A domain whose DNS is on Cloudflare, with a wildcard record `*.<domain>`
  pointing at the server.
- A Cloudflare API token with **Zone → DNS → Edit** permission on that zone.

## Server setup

On a Debian or Ubuntu server:

```sh
curl -fsSL https://github.com/vwkyc/x2rp/releases/latest/download/install.sh | sudo bash
```

The installer downloads the release binary for the server's architecture
(x86_64 or aarch64). A first install asks for:

1. the base domain, e.g. `example.com`;
2. an admin password (12–128 characters);
3. the Cloudflare API token.

Run the same command again to upgrade to the latest release. To remove x2rp and
all of its data:

```sh
curl -fsSL https://github.com/vwkyc/x2rp/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

The service runs as the unprivileged `x2rp` user, and its state lives in
`/var/lib/x2rp`. Once a certificate has been issued, the console is at
`https://x2rp.example.com`.

```sh
x2rp status   # systemd state
x2rp logs     # follow the journal
```

## Routes

Each route maps `<subdomain>.<domain>` to an upstream origin (no path or
query):

| Via       | Upstream                                                            |
|-----------|---------------------------------------------------------------------|
| This host | `http(s)://` on loopback (`127.0.0.1`, `::1`, `localhost`), except port 8800 |
| Connector | `http://` on the connector's LAN or loopback                        |

Link-local, multicast and cloud-metadata addresses are always refused.

**Allowed clients** takes IPs and CIDR blocks separated by commas. Leave it
empty to allow everyone. A client outside the list gets a plain `403`.

## Connectors

1. In the console, go to **Connectors**, then **New connector**, and copy the
   install command. The token is shown once.
2. Run it on the private host. It installs the connector release that matches
   the server's version:

   ```sh
   curl -fsSL https://github.com/vwkyc/x2rp/releases/download/v1.0.0/install-connector.sh | sudo bash -s -- --server https://x2rp.example.com --token '<token>'
   ```

Keep connectors on the server's version. The installer with no arguments
upgrades a connector in place and keeps its config, so after upgrading the
server to the latest release:

```sh
curl -fsSL https://github.com/vwkyc/x2rp/releases/latest/download/install-connector.sh | sudo bash
```

To remove a connector:

```sh
curl -fsSL https://github.com/vwkyc/x2rp/releases/latest/download/install-connector.sh | sudo bash -s -- --uninstall
```

The connector keeps its config in `/etc/x2rp-connector/config.json` and
reconnects with backoff. **WebSocket only** skips QUIC on networks that block or
throttle UDP. **Regenerate token** revokes the old token and ends its session.

## Ports

| Port           | Purpose                                             |
|----------------|-----------------------------------------------------|
| TCP 443        | HTTPS proxy, admin console, WebSocket connector transport |
| UDP 443        | QUIC connector transport                            |
| TCP 80         | Redirect to HTTPS; optional to expose, since certificates use DNS-01 |
| 127.0.0.1:8800 | Admin API (loopback only)                           |

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
scripts/build.sh all                     # dist/x2rp-<arch>, dist/x2rp-connector-<arch>
scripts/build.sh server --arch aarch64
```

`scripts/build.sh` produces static musl binaries and downloads the cross
toolchain on first use. Either installer run from a directory holding the
matching `x2rp-<arch>` or `x2rp-connector-<arch>` installs that binary instead of
downloading one, e.g. `sudo ./install.sh` next to a copy of `dist/x2rp-x86_64`.

The workspace has three crates. `crates/server` is the proxy, admin API and
console. `crates/connector` is the connector. `crates/proto` holds the tunnel
framing, obfuscation and target checks shared by both. The console sources in
`web/` are embedded into the server binary at build time.

## Acknowledgements

x2rp is built on top of several open-source technologies:

- **[Pingora](https://github.com/cloudflare/pingora)** (Cloudflare) - Asynchronous Rust proxy engine powering HTTP/HTTPS routing, connection pooling, and request filters.
- **[Quinn](https://github.com/quinn-rs/quinn)** - Pure-Rust async QUIC transport implementation for relay connectors.
- **[Tokio](https://tokio.rs/)** & **[Axum](https://github.com/tokio-rs/axum)** - Async runtime, event loops, and control plane API framework.
- **[Rustls](https://github.com/rustls/rustls)** & **[ring](https://github.com/briansmith/ring)** - Memory-safe TLS engine and its cryptographic backend.
- **[instant-acme](https://github.com/djc/instant-acme)** - Native Let's Encrypt / ACME client for automated DNS-01 certificate management.
- **[mimalloc](https://github.com/purpleprotocol/mimalloc_rust)** (Microsoft **[mimalloc](https://github.com/microsoft/mimalloc)**) - Compact, high-performance global memory allocator used across server and connector binaries.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later).
