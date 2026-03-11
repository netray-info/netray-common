use axum::extract::Request;
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
    let strict_csp =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'".to_string();

    let relaxed_csp = if config.extra_script_src.is_empty() {
        strict_csp.clone()
    } else {
        let extra = config.extra_script_src.join(" ");
        format!(
            "default-src 'self'; script-src 'self' {extra}; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        )
    };

    let prefix = config.relaxed_csp_path_prefix;
    let include_pp = config.include_permissions_policy;

    move |request: Request, next: Next| {
        let strict_csp = strict_csp.clone();
        let relaxed_csp = relaxed_csp.clone();
        let prefix = prefix.clone();

        Box::pin(async move {
            let is_relaxed_path = request.uri().path().starts_with(&prefix);

            let mut response = next.run(request).await;
            let headers = response.headers_mut();

            let csp = if is_relaxed_path {
                &relaxed_csp
            } else {
                &strict_csp
            };
            headers.insert(
                axum::http::header::CONTENT_SECURITY_POLICY,
                csp.parse().expect("valid CSP header value"),
            );

            headers.insert(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".parse().expect("valid header value"),
            );

            headers.insert(
                axum::http::header::X_FRAME_OPTIONS,
                "DENY".parse().expect("valid header value"),
            );

            headers.insert(
                axum::http::header::REFERRER_POLICY,
                "strict-origin-when-cross-origin"
                    .parse()
                    .expect("valid header value"),
            );

            headers.insert(
                axum::http::header::STRICT_TRANSPORT_SECURITY,
                "max-age=31536000; includeSubDomains"
                    .parse()
                    .expect("valid header value"),
            );

            if include_pp {
                headers.insert(
                    axum::http::HeaderName::from_static("permissions-policy"),
                    "geolocation=(), microphone=(), camera=(), payment=()"
                        .parse()
                        .expect("valid header value"),
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
