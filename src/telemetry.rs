//! Shared telemetry initialisation — tracing-subscriber + optional OTel OTLP export.
//!
//! When `config.enabled = true`, an OTLP exporter is started and bridged into
//! the tracing subscriber. When disabled, only the fmt layer + env filter are
//! active — zero OTel overhead.

use std::sync::OnceLock;

use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use serde::Deserialize;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Log output format.
///
/// Configurable via `telemetry.log_format` in the service TOML config.
///
/// - `text` (default): human-readable, colour-coded output for local development.
/// - `json`: structured JSON lines for log aggregators (Loki, CloudWatch, Datadog).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Telemetry configuration shared across services.
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    #[serde(default)]
    pub log_format: LogFormat,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: default_otlp_endpoint(),
            service_name: String::new(),
            sample_rate: default_sample_rate(),
            log_format: LogFormat::default(),
        }
    }
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4318".to_owned()
}

fn default_sample_rate() -> f64 {
    1.0
}

/// Initialise the tracing subscriber with an optional OpenTelemetry layer.
///
/// `default_filter` is used as the fallback when `RUST_LOG` is not set
/// (e.g. `"prism=info,tower_http=info"`).
///
/// The caller is responsible for calling [`shutdown`] on graceful shutdown
/// to flush pending spans.
pub fn init_subscriber(config: &TelemetryConfig, default_filter: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| default_filter.into());

    let use_json = config.log_format == LogFormat::Json;

    if config.enabled {
        let otel_layer = init_otel_layer(config).expect("failed to initialize OpenTelemetry");

        if use_json {
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().json())
                .with(env_filter)
                .init();
        } else {
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer())
                .with(env_filter)
                .init();
        }
    } else if use_json {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().json())
            .with(env_filter)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(env_filter)
            .init();
    }
}

/// Build the OpenTelemetry tracing layer.
fn init_otel_layer(
    config: &TelemetryConfig,
) -> Result<
    tracing_opentelemetry::OpenTelemetryLayer<
        tracing_subscriber::Registry,
        opentelemetry_sdk::trace::Tracer,
    >,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let sampler = if (config.sample_rate - 1.0).abs() < f64::EPSILON {
        Sampler::AlwaysOn
    } else if config.sample_rate == 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_rate)
    };

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp_endpoint)
        .build()?;

    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer(config.service_name.clone());
    global::set_tracer_provider(provider.clone());
    let _ = TRACER_PROVIDER.set(provider);

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    Ok(layer)
}

/// Flush pending spans and shut down the global tracer provider.
pub fn shutdown() {
    if let Some(provider) = TRACER_PROVIDER.get() {
        if let Err(e) = provider.force_flush() {
            tracing::warn!(error = %e, "failed to flush OTel spans on shutdown");
        }
        if let Err(e) = provider.shutdown() {
            tracing::warn!(error = %e, "failed to shut down OTel provider");
        }
    }
}
