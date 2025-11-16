use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, Encoder, HistogramVec, TextEncoder,
};
use std::time::Instant;

lazy_static! {
    /// Counter for authentication attempts
    /// Labels: result (success, failure, error)
    pub static ref AUTH_ATTEMPTS_TOTAL: CounterVec = register_counter_vec!(
        "auth_attempts_total",
        "Total number of authentication attempts",
        &["result"]
    )
    .expect("Failed to create auth_attempts_total metric");

    /// Counter for authentication failures
    /// Labels: reason (missing_token, invalid_token, expired_token, etc.)
    pub static ref AUTH_FAILURES_TOTAL: CounterVec = register_counter_vec!(
        "auth_failures_total",
        "Total number of authentication failures",
        &["reason"]
    )
    .expect("Failed to create auth_failures_total metric");

    /// Histogram for authentication operation latency
    pub static ref AUTH_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "auth_duration_seconds",
        "Duration of authentication operations in seconds",
        &["operation"]
    )
    .expect("Failed to create auth_duration_seconds metric");

    /// Counter for authorization decisions
    /// Labels: decision (allowed, denied)
    pub static ref AUTHZ_DECISIONS_TOTAL: CounterVec = register_counter_vec!(
        "authz_decisions_total",
        "Total number of authorization decisions",
        &["decision"]
    )
    .expect("Failed to create authz_decisions_total metric");

    /// Histogram for authorization operation latency
    pub static ref AUTHZ_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "authz_duration_seconds",
        "Duration of authorization operations in seconds",
        &["operation"]
    )
    .expect("Failed to create authz_duration_seconds metric");

    /// Counter for HTTP requests
    /// Labels: method, path, status
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["method", "status"]
    )
    .expect("Failed to create http_requests_total metric");

    /// Histogram for HTTP request duration
    /// Labels: method, path
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "Duration of HTTP requests in seconds",
        &["method"]
    )
    .expect("Failed to create http_request_duration_seconds metric");

    /// Counter for upstream requests
    /// Labels: service, status
    pub static ref UPSTREAM_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "upstream_requests_total",
        "Total number of upstream requests",
        &["service", "status"]
    )
    .expect("Failed to create upstream_requests_total metric");

    /// Histogram for upstream request duration
    /// Labels: service
    pub static ref UPSTREAM_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "upstream_request_duration_seconds",
        "Duration of upstream requests in seconds",
        &["service"]
    )
    .expect("Failed to create upstream_request_duration_seconds metric");
}

/// Helper struct to measure operation duration
pub struct DurationTimer {
    start: Instant,
}

impl DurationTimer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn observe_duration(&self, histogram: &HistogramVec, labels: &[&str]) {
        let duration = self.start.elapsed().as_secs_f64();
        histogram.with_label_values(labels).observe(duration);
    }
}

impl Default for DurationTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Record successful authentication
pub fn record_auth_success() {
    AUTH_ATTEMPTS_TOTAL.with_label_values(&["success"]).inc();
}

/// Record failed authentication with reason
pub fn record_auth_failure(reason: &str) {
    AUTH_ATTEMPTS_TOTAL.with_label_values(&["failure"]).inc();
    AUTH_FAILURES_TOTAL.with_label_values(&[reason]).inc();
}

/// Record authentication error
pub fn record_auth_error() {
    AUTH_ATTEMPTS_TOTAL.with_label_values(&["error"]).inc();
}

/// Record authorization decision
pub fn record_authz_decision(allowed: bool) {
    let decision = if allowed { "allowed" } else { "denied" };
    AUTHZ_DECISIONS_TOTAL.with_label_values(&[decision]).inc();
}

/// Export all metrics in Prometheus text format
pub fn export_metrics() -> Result<String, Box<dyn std::error::Error>> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_metrics() {
        record_auth_success();
        record_auth_failure("invalid_token");
        record_auth_error();

        // Verify metrics can be exported
        let metrics = export_metrics().expect("Failed to export metrics");
        assert!(metrics.contains("auth_attempts_total"));
        assert!(metrics.contains("auth_failures_total"));
    }

    #[test]
    fn test_authz_metrics() {
        record_authz_decision(true);
        record_authz_decision(false);

        let metrics = export_metrics().expect("Failed to export metrics");
        assert!(metrics.contains("authz_decisions_total"));
    }

    #[test]
    fn test_duration_timer() {
        let timer = DurationTimer::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        timer.observe_duration(&AUTH_DURATION_SECONDS, &["test"]);

        let metrics = export_metrics().expect("Failed to export metrics");
        assert!(metrics.contains("auth_duration_seconds"));
    }
}
