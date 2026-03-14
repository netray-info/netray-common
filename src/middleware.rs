use axum::extract::MatchedPath;
use axum::http::{HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;

/// Newtype for the per-request ID stored in request extensions.
#[derive(Clone)]
pub struct RequestId(pub String);

fn is_valid_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Axum middleware that injects `X-Request-Id` on every request and response.
///
/// If the incoming `X-Request-Id` header is present and valid (non-empty, ≤64
/// chars, only alphanumeric/hyphen/underscore), it is reused. Otherwise a UUID
/// v7 string is generated. The ID is stored in request extensions as
/// [`RequestId`] so downstream handlers can extract it.
pub async fn request_id(mut req: Request<axum::body::Body>, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid_request_id(s))
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    // Also propagate the (possibly generated) ID into the request header so
    // the TraceLayer can read it from headers for span correlation.
    if let Ok(val) = HeaderValue::from_str(&id) {
        req.headers_mut().insert("x-request-id", val);
    }

    let mut response = next.run(req).await;

    if let Ok(val) = HeaderValue::from_str(&id) {
        response.headers_mut().insert("x-request-id", val);
    }

    response
}

/// Axum middleware that records HTTP request metrics using the `metrics` crate.
///
/// Uses [`MatchedPath`] (not raw URI) for the `path` label to avoid unbounded
/// cardinality from dynamic path segments. Falls back to `"unknown"` for
/// requests that don't match any route (e.g. 404s).
///
/// Emits:
/// - `{prefix}_http_requests_total{method, path, status}` counter
/// - `{prefix}_http_request_duration_seconds{method, path}` histogram
pub async fn http_metrics(
    prefix: &'static str,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());

    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    let requests_key = format!("{prefix}_http_requests_total");
    let duration_key = format!("{prefix}_http_request_duration_seconds");

    metrics::counter!(requests_key, "method" => method.clone(), "path" => path.clone(), "status" => status).increment(1);
    metrics::histogram!(duration_key, "method" => method, "path" => path).record(duration);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_request_ids() {
        assert!(is_valid_request_id("abc-123_XYZ"));
        assert!(is_valid_request_id("a"));
        assert!(is_valid_request_id(&"a".repeat(64)));
    }

    #[test]
    fn invalid_request_ids() {
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id(&"a".repeat(65)));
        assert!(!is_valid_request_id("has space"));
        assert!(!is_valid_request_id("has/slash"));
        assert!(!is_valid_request_id("has.dot"));
    }
}
