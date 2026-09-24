//! The admin console, embedded at build time.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// (file name, content type, body) for every file in `web/`.
const ASSETS: [(&str, &str, &[u8]); 5] = [
    (
        "admin.html",
        "text/html; charset=utf-8",
        include_bytes!("../../../web/admin.html"),
    ),
    (
        "admin.css",
        "text/css",
        include_bytes!("../../../web/admin.css"),
    ),
    (
        "app.js",
        "text/javascript",
        include_bytes!("../../../web/app.js"),
    ),
    (
        "login.html",
        "text/html; charset=utf-8",
        include_bytes!("../../../web/login.html"),
    ),
    (
        "login.js",
        "text/javascript",
        include_bytes!("../../../web/login.js"),
    ),
];

/// `/` is the console; any other path names a file.
fn file_name(path: &str) -> &str {
    match path.strip_prefix('/').unwrap_or(path) {
        "" => "admin.html",
        name => name,
    }
}

/// Only the console page needs an admin session; its assets and the login page are
/// public (the data all comes from the authenticated API).
pub fn requires_auth(path: &str) -> bool {
    file_name(path) == "admin.html"
}

pub fn serve_static(path: &str) -> Response {
    let name = file_name(path);
    let Some((_, mime, body)) = ASSETS.iter().find(|(file, ..)| *file == name) else {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    };
    let mut response = ([(header::CONTENT_TYPE, *mime)], *body).into_response();
    if name.ends_with(".html") {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_console_page_needs_a_session() {
        for protected in ["/", "/admin.html"] {
            assert!(requires_auth(protected), "{protected}");
        }
        for public in [
            "/login.html",
            "/app.js",
            "/admin.css",
            "//admin.html",
            "/../x",
        ] {
            assert!(!requires_auth(public), "{public}");
        }
        // A path that dodges the check must not reach the console either.
        assert_eq!(serve_static("//admin.html").status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn html_documents_are_served_no_store() {
        let response = serve_static("/");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
}
