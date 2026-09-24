pub const ADMIN_APP_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'none'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'";

/// Applied to every response by both paths, as tower layers on the Axum admin app
/// (`main.rs`) and by [`append_standard_security_headers`] on proxied responses,
/// so the two cannot drift.
pub const STANDARD_RESPONSE_HEADERS: [(http::HeaderName, &str); 4] = [
    (
        http::header::STRICT_TRANSPORT_SECURITY,
        "max-age=63072000; includeSubDomains",
    ),
    (http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (http::header::REFERRER_POLICY, "no-referrer"),
    (http::header::X_FRAME_OPTIONS, "SAMEORIGIN"),
];

/// Adds any standard security header the upstream response did not set.
pub fn append_standard_security_headers(resp: &mut pingora_http::ResponseHeader) {
    for (name, value) in STANDARD_RESPONSE_HEADERS {
        if !resp.headers.contains_key(&name) {
            let _ = resp.insert_header(name, value);
        }
    }
}
