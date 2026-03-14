//! Shared CORS layer construction.

use tower_http::cors::CorsLayer;

/// Returns a restrictive `CorsLayer` that allows only GET and POST with
/// standard content-type/accept headers.
///
/// No origin allowlist is configured, so `CorsLayer` rejects all cross-origin
/// requests by default. Same-origin requests from an embedded SPA never trigger
/// CORS preflight and are unaffected.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT])
        .max_age(std::time::Duration::from_secs(3600))
}
