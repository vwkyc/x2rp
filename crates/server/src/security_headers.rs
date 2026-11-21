use axum::{body::Body, http::Request, middleware::Next, response::Response};
use http::{HeaderName, HeaderValue, header};

pub const ADMIN_APP_CSP: &str = "default-src 'self'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// Applied to every response by both paths: [`admin_security_headers_middleware`]
/// on the Axum admin app and [`append_standard_security_headers`] on Pingora
/// proxied responses, so the two cannot drift.
pub const STANDARD_RESPONSE_HEADERS: [(HeaderName, &str); 4] = [
    (
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=63072000; includeSubDomains",
    ),
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::REFERRER_POLICY, "no-referrer"),
    (header::X_FRAME_OPTIONS, "SAMEORIGIN"),
];

/// Extra browser-isolation headers applied only to x2rp's own admin responses
/// (never forced on proxied third-party origins that may legitimately embed or use APIs).
const ADMIN_EXTRA_HEADERS: [(&str, &str); 3] = [
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    ),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
];

/// Axum middleware applying CSP + standard + browser-isolation headers to admin responses.
pub async fn admin_security_headers_middleware(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(ADMIN_APP_CSP));
    for (name, value) in STANDARD_RESPONSE_HEADERS {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    for (name, value) in ADMIN_EXTRA_HEADERS {
        headers
            .entry(HeaderName::from_static(name))
            .or_insert(HeaderValue::from_static(value));
    }
    resp
}

/// Axum middleware ensuring `/api/*` responses default to `Cache-Control: no-store`.
pub async fn api_no_store_middleware(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    resp
}

/// Applies standard security headers to a Pingora response.
/// Always enforces HSTS and `X-Content-Type-Options: nosniff` so compromised or
/// misconfigured upstream origins cannot downgrade transport security or MIME sniffing;
/// preserves origin-provided framing/referrer policies when already set.
pub fn append_standard_security_headers(resp: &mut pingora_http::ResponseHeader) {
    for (name, value) in STANDARD_RESPONSE_HEADERS {
        let force =
            name == header::STRICT_TRANSPORT_SECURITY || name == header::X_CONTENT_TYPE_OPTIONS;
        if force || !resp.headers.contains_key(&name) {
            let _ = resp.insert_header(name, value);
        }
    }
}
