//! Metrics namespace marker trait for service-specific metric prefixes.

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Marker trait for types that supply a static Prometheus/metrics prefix.
///
/// Implementing this trait on a unit struct lets callers pass a type instead
/// of a `&'static str` when wiring up metrics middleware or rate-limit
/// helpers. The existing `http_metrics` and `check_keyed_cost` function
/// signatures are unchanged — this trait is additive for future consumers.
///
/// The trait is sealed: only types that also implement the internal
/// `sealed::Sealed` bound can implement it, which prevents downstream crates
/// from accidentally implementing it on unrelated types.
pub trait MetricsNamespace: sealed::Sealed {
    fn prefix() -> &'static str;
}
