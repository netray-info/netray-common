# netray-common

Shared utilities for the [netray.info](https://netray.info) service ecosystem.

## Modules

| Module | Purpose |
|--------|---------|
| `ip_extract` | Extract real client IP from proxy headers (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) with trusted-proxy CIDR matching |
| `error` | Structured JSON error responses (`ApiError` trait + `into_error_response`) with `Retry-After` support |
| `rate_limit` | Keyed and global rate limiting wrappers around `governor` with metrics integration |
| `security_headers` | Axum middleware that sets CSP, HSTS, X-Frame-Options, and other security headers |

## Usage

```sh
cargo add netray-common
```

### IP extraction

```rust
use netray_common::ip_extract::IpExtractor;

let extractor = IpExtractor::new(&[
    "10.0.0.0/8".to_string(),
    "172.16.0.0/12".to_string(),
]).unwrap();

let client_ip = extractor.extract(&headers, peer_addr);
```

### Error responses

```rust
use netray_common::error::{ApiError, into_error_response};

impl ApiError for MyError {
    fn status_code(&self) -> StatusCode { /* ... */ }
    fn error_code(&self) -> &'static str { /* ... */ }
}

// Produces: {"error": {"code": "...", "message": "..."}}
let response = into_error_response(&my_error);
```

### Rate limiting

```rust
use netray_common::rate_limit::{KeyedLimiter, check_keyed_cost};

let limiter: KeyedLimiter<IpAddr> = RateLimiter::keyed(quota);
check_keyed_cost(&limiter, &client_ip, cost, "per_ip", "myservice")?;
```

### Security headers

```rust
use netray_common::security_headers::{SecurityHeadersConfig, security_headers_layer};

let layer_fn = security_headers_layer(SecurityHeadersConfig::default());
let app = Router::new()
    .route("/", get(handler))
    .layer(middleware::from_fn(move |req, next| {
        let f = layer_fn.clone();
        async move { f(req, next).await }
    }));
```

## MSRV

1.75

## License

MIT
