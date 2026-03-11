use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// Configuration for the security headers middleware.
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// Additional `script-src` origins to include in CSP (e.g. `"https://cdn.jsdelivr.net"`).
    /// Applied to paths matching `relaxed_csp_path_prefix`.
    pub extra_script_src: Vec<String>,

    /// Path prefix that triggers the relaxed CSP with `extra_script_src`.
    /// Defaults to `"/docs"` if empty.
    pub relaxed_csp_path_prefix: String,

    /// Whether to include the `Permissions-Policy` header.
    pub include_permissions_policy: bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            extra_script_src: Vec::new(),
            relaxed_csp_path_prefix: "/docs".to_string(),
            include_permissions_policy: false,
        }
    }
}

/// Build a security headers middleware function from the given config.
///
/// Returns an async closure suitable for `axum::middleware::from_fn`.
///
/// Headers applied:
/// - `Content-Security-Policy`: Restricts resource loading to same origin.
///   `style-src 'unsafe-inline'` is included for inline styles.
///   Paths matching `relaxed_csp_path_prefix` get additional `script-src` origins.
/// - `X-Content-Type-Options: nosniff`
/// - `X-Frame-Options: DENY`
/// - `Referrer-Policy: strict-origin-when-cross-origin`
/// - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
/// - `Permissions-Policy` (optional, when `include_permissions_policy` is true)
pub fn security_headers_layer(
    config: SecurityHeadersConfig,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone
       + Send
       + 'static {
    let valid_extra: Vec<String> = config
        .extra_script_src
        .into_iter()
        .filter(|src| {
            if src.contains(';') || src.contains('\n') || src.contains('\r') || src.is_empty() {
                tracing::warn!(value = %src, "invalid extra_script_src entry skipped");
                false
            } else {
                true
            }
        })
        .collect();

    let strict_csp =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'".to_string();

    let relaxed_csp = if valid_extra.is_empty() {
        strict_csp.clone()
    } else {
        let extra = valid_extra.join(" ");
        format!(
            "default-src 'self'; script-src 'self' {extra}; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        )
    };

    let strict_csp_val: HeaderValue = strict_csp.parse().expect("valid CSP header value");
    let relaxed_csp_val: HeaderValue = relaxed_csp.parse().expect("valid CSP header value");
    let nosniff: HeaderValue = "nosniff".parse().expect("valid header value");
    let deny: HeaderValue = "DENY".parse().expect("valid header value");
    let referrer: HeaderValue = "strict-origin-when-cross-origin"
        .parse()
        .expect("valid header value");
    let hsts: HeaderValue = "max-age=31536000; includeSubDomains"
        .parse()
        .expect("valid header value");
    let pp_val: Option<HeaderValue> = if config.include_permissions_policy {
        Some(
            "geolocation=(), microphone=(), camera=(), payment=()"
                .parse()
                .expect("valid header value"),
        )
    } else {
        None
    };

    let prefix = config.relaxed_csp_path_prefix;
    let prefix_with_slash = format!("{prefix}/");

    move |request: Request, next: Next| {
        let strict_csp_val = strict_csp_val.clone();
        let relaxed_csp_val = relaxed_csp_val.clone();
        let nosniff = nosniff.clone();
        let deny = deny.clone();
        let referrer = referrer.clone();
        let hsts = hsts.clone();
        let pp_val = pp_val.clone();
        let prefix = prefix.clone();
        let prefix_with_slash = prefix_with_slash.clone();

        Box::pin(async move {
            let path = request.uri().path();
            let is_relaxed_path = path == prefix || path.starts_with(&prefix_with_slash);

            let mut response = next.run(request).await;
            let headers = response.headers_mut();

            let csp = if is_relaxed_path {
                relaxed_csp_val
            } else {
                strict_csp_val
            };
            headers.insert(axum::http::header::CONTENT_SECURITY_POLICY, csp);
            headers.insert(axum::http::header::X_CONTENT_TYPE_OPTIONS, nosniff);
            headers.insert(axum::http::header::X_FRAME_OPTIONS, deny);
            headers.insert(axum::http::header::REFERRER_POLICY, referrer);
            headers.insert(axum::http::header::STRICT_TRANSPORT_SECURITY, hsts);

            if let Some(pp) = pp_val {
                headers.insert(
                    axum::http::HeaderName::from_static("permissions-policy"),
                    pp,
                );
            }

            response
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    async fn make_response(config: SecurityHeadersConfig, path: &str) -> Response {
        let layer_fn = security_headers_layer(config);
        let app = Router::new()
            .route("/test", get(ok_handler))
            .route("/docs/test", get(ok_handler))
            .layer(middleware::from_fn(move |req, next| {
                let f = layer_fn.clone();
                async move { f(req, next).await }
            }));

        let request = HttpRequest::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();

        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn sets_all_base_headers() {
        let response = make_response(SecurityHeadersConfig::default(), "/test").await;

        assert_eq!(response.status(), StatusCode::OK);

        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("frame-ancestors 'none'"));

        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            response.headers().get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn no_permissions_policy_by_default() {
        let response = make_response(SecurityHeadersConfig::default(), "/test").await;
        assert!(response.headers().get("permissions-policy").is_none());
    }

    #[tokio::test]
    async fn includes_permissions_policy_when_configured() {
        let config = SecurityHeadersConfig {
            include_permissions_policy: true,
            ..Default::default()
        };
        let response = make_response(config, "/test").await;
        let pp = response
            .headers()
            .get("permissions-policy")
            .expect("Permissions-Policy header present")
            .to_str()
            .unwrap();
        assert!(pp.contains("geolocation=()"));
        assert!(pp.contains("camera=()"));
    }

    #[tokio::test]
    async fn relaxed_csp_on_docs_path() {
        let config = SecurityHeadersConfig {
            extra_script_src: vec!["https://cdn.jsdelivr.net".to_string()],
            ..Default::default()
        };
        let response = make_response(config, "/docs/test").await;
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("https://cdn.jsdelivr.net"));
    }

    #[tokio::test]
    async fn relaxed_csp_on_custom_prefix() {
        let config = SecurityHeadersConfig {
            extra_script_src: vec!["https://cdn.example.com".to_string()],
            relaxed_csp_path_prefix: "/api-docs".to_string(),
            ..Default::default()
        };
        let layer_fn = security_headers_layer(config);
        let app = Router::new()
            .route("/api-docs/test", get(ok_handler))
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn(move |req, next| {
                let f = layer_fn.clone();
                async move { f(req, next).await }
            }));

        let req = HttpRequest::builder()
            .uri("/api-docs/test")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("https://cdn.example.com"));

        let req = HttpRequest::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!csp.contains("cdn.example.com"));
    }

    #[tokio::test]
    async fn strict_csp_on_non_docs_path() {
        let config = SecurityHeadersConfig {
            extra_script_src: vec!["https://cdn.jsdelivr.net".to_string()],
            ..Default::default()
        };
        let response = make_response(config, "/test").await;
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!csp.contains("cdn.jsdelivr.net"));
    }
}
