#[cfg(not(target_os = "linux"))]
compile_error!(
    "x2rp is Linux-only (targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl)"
);

pub mod allowlist;
pub mod api;
pub mod auth;
pub mod connector_manager;
pub mod http_middleware;
pub mod proxy;
pub mod rate_limit;
pub mod security_headers;
pub mod static_files;
pub mod tls;
pub mod transport;
