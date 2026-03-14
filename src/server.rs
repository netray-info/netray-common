/// Shared server utilities: graceful shutdown signal, metrics server, and static file handler.

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

/// Waits for SIGINT (Ctrl-C) or SIGTERM, whichever comes first.
/// Use with axum's `with_graceful_shutdown`.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }

    tracing::info!("shutdown signal received");
}

// ---------------------------------------------------------------------------
// Prometheus metrics server
// ---------------------------------------------------------------------------

#[cfg(feature = "prometheus")]
pub use prometheus_server::serve_metrics;

#[cfg(feature = "prometheus")]
mod prometheus_server {
    use axum::Router;
    use std::net::SocketAddr;

    /// Bind a metrics-only HTTP server on the given address.
    /// Exposes a single `/metrics` route.
    /// Returns `Err` if the socket cannot be bound or the recorder fails to install.
    pub async fn serve_metrics(
        addr: SocketAddr,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
        let handle = builder.install_recorder()?;

        let app = Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let handle = handle.clone();
                async move { handle.render() }
            }),
        );

        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(addr = %addr, "metrics server listening");

        axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown(shutdown))
            .await?;

        Ok(())
    }

    async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
        let _ = rx.wait_for(|v| *v).await;
    }
}

// ---------------------------------------------------------------------------
// Static file handler (SPA)
// ---------------------------------------------------------------------------

#[cfg(feature = "spa")]
pub use spa::static_handler;

#[cfg(feature = "spa")]
mod spa {
    use axum::response::IntoResponse;

    /// Returns an axum handler that serves embedded assets from a `RustEmbed` type.
    ///
    /// - `index.html` and the root path get `Cache-Control: no-cache`.
    /// - Other assets get `Cache-Control: public, max-age=31536000, immutable`.
    /// - Unknown paths fall back to `index.html` for SPA client-side routing.
    pub fn static_handler<E: rust_embed::RustEmbed>() -> impl Fn(axum::http::Uri) -> std::future::Ready<axum::response::Response> + Clone + Send + Sync + 'static {
        move |uri: axum::http::Uri| {
            std::future::ready(handle_static::<E>(uri))
        }
    }

    fn handle_static<E: rust_embed::RustEmbed>(uri: axum::http::Uri) -> axum::response::Response {
        let path = uri.path().trim_start_matches('/');

        if path.is_empty() || path == "index.html" {
            return serve_index::<E>();
        }

        match E::get(path) {
            Some(file) => {
                let mime = mime_guess::from_path(path).first_or_octet_stream();
                let cache = "public, max-age=31536000, immutable";
                (
                    [
                        (axum::http::header::CONTENT_TYPE, mime.as_ref().to_string()),
                        (axum::http::header::CACHE_CONTROL, cache.to_string()),
                    ],
                    file.data.to_vec(),
                )
                    .into_response()
            }
            None => serve_index::<E>(),
        }
    }

    fn serve_index<E: rust_embed::RustEmbed>() -> axum::response::Response {
        match E::get("index.html") {
            Some(index) => (
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "text/html; charset=utf-8".to_string(),
                    ),
                    (
                        axum::http::header::CACHE_CONTROL,
                        "no-cache".to_string(),
                    ),
                ],
                index.data.to_vec(),
            )
                .into_response(),
            None => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "frontend not found",
            )
                .into_response(),
        }
    }
}
