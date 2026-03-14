use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// JSON body returned for all error responses.
///
/// Wire format: `{"error": {"code": "...", "message": "..."}}`
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct ErrorResponse {
    pub error: ErrorInfo,
}

/// Error detail contained in an error response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct ErrorInfo {
    /// Machine-readable error code (e.g. `INVALID_DOMAIN`).
    pub code: &'static str,
    /// Human-readable error message.
    pub message: String,
}

/// Trait for application-specific error types that can be rendered as
/// structured JSON error responses.
///
/// Each project defines its own error enum and implements this trait.
/// The shared `IntoResponse` implementation (via [`into_error_response`])
/// handles JSON serialization, status codes, and the `Retry-After` header
/// for rate-limited responses.
pub trait ApiError: std::fmt::Display {
    /// HTTP status code for this error variant.
    fn status_code(&self) -> StatusCode;

    /// Machine-readable error code string (e.g. `"INVALID_DOMAIN"`).
    fn error_code(&self) -> &'static str;

    /// If this is a rate-limited error, return the retry-after duration in seconds.
    fn retry_after_secs(&self) -> Option<u64> {
        None
    }
}

/// Convert any [`ApiError`] into an axum [`Response`].
///
/// Produces a JSON body of the form:
/// ```json
/// {"error": {"code": "ERROR_CODE", "message": "human-readable message"}}
/// ```
///
/// For rate-limited responses (when `retry_after_secs()` returns `Some`),
/// includes the `Retry-After` header per RFC 6585.
pub fn into_error_response(err: &impl ApiError) -> Response {
    let status = err.status_code();

    if status.is_server_error() {
        tracing::error!(error = %err, "internal server error");
    } else if status.is_client_error() {
        tracing::warn!(error = %err, "client error");
    }

    let body = ErrorResponse {
        error: ErrorInfo {
            code: err.error_code(),
            message: err.to_string(),
        },
    };

    let mut response = (status, axum::Json(body)).into_response();

    if let Some(secs) = err.retry_after_secs() {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from(secs),
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[derive(Debug)]
    enum TestError {
        BadInput(String),
        RateLimited { retry_after: u64 },
        Internal(String),
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::BadInput(msg) => write!(f, "bad input: {msg}"),
                Self::RateLimited { .. } => write!(f, "rate limited"),
                Self::Internal(msg) => write!(f, "internal error: {msg}"),
            }
        }
    }

    impl ApiError for TestError {
        fn status_code(&self) -> StatusCode {
            match self {
                Self::BadInput(_) => StatusCode::BAD_REQUEST,
                Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
                Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }

        fn error_code(&self) -> &'static str {
            match self {
                Self::BadInput(_) => "BAD_INPUT",
                Self::RateLimited { .. } => "RATE_LIMITED",
                Self::Internal(_) => "INTERNAL_ERROR",
            }
        }

        fn retry_after_secs(&self) -> Option<u64> {
            match self {
                Self::RateLimited { retry_after } => Some(*retry_after),
                _ => None,
            }
        }
    }

    async fn body_json(err: TestError) -> serde_json::Value {
        let response = into_error_response(&err);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn into_parts(
        err: TestError,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        let response = into_error_response(&err);
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, headers, body)
    }

    #[tokio::test]
    async fn bad_input_is_400() {
        let response = into_error_response(&TestError::BadInput("oops".into()));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rate_limited_is_429() {
        let response = into_error_response(&TestError::RateLimited { retry_after: 5 });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn internal_is_500() {
        let response = into_error_response(&TestError::Internal("boom".into()));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn body_has_error_code_and_message() {
        let body = body_json(TestError::BadInput("test".into())).await;
        assert_eq!(body["error"]["code"], "BAD_INPUT");
        assert!(body["error"]["message"].as_str().unwrap().contains("test"));
        assert_eq!(body.as_object().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rate_limited_includes_retry_after_header() {
        let (status, headers, _) =
            into_parts(TestError::RateLimited { retry_after: 42 }).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let retry_after = headers
            .get(axum::http::header::RETRY_AFTER)
            .expect("Retry-After header must be present");
        let value: u64 = retry_after.to_str().unwrap().parse().unwrap();
        assert_eq!(value, 42);
    }

    #[tokio::test]
    async fn non_rate_limited_has_no_retry_after() {
        let (_, headers, _) = into_parts(TestError::BadInput("x".into())).await;
        assert!(headers.get(axum::http::header::RETRY_AFTER).is_none());
    }

    #[tokio::test]
    async fn error_response_has_json_content_type() {
        let response = into_error_response(&TestError::BadInput("test".into()));
        let ct = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("Content-Type header must be present")
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/json"),
            "expected application/json, got {ct}"
        );
    }
}
