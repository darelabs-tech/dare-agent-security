//! Streamable HTTP client policy: TLS required, redirects disabled.

use std::time::Duration;

use super::adapter_error::AdapterError;
use super::DiscoveryTimeouts;

/// Default maximum HTTP/JSON-RPC response size (1 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_048_576;

/// Safe-by-default Streamable HTTP transport policy.
///
/// There is no public setter that disables TLS or enables redirects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTransportConfig {
    tls_verify: bool,
    follow_redirects: bool,
    https_only: bool,
    connect_timeout: Duration,
    request_timeout: Duration,
    max_response_bytes: usize,
    loopback_http_tests: bool,
}

impl HttpTransportConfig {
    /// TLS verification on, redirects off, HTTPS-only, bounded timeouts.
    pub fn new() -> Self {
        Self {
            tls_verify: true,
            follow_redirects: false,
            https_only: true,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            loopback_http_tests: false,
        }
    }

    /// TEST ONLY. Allows cleartext `http://` to loopback hosts.
    ///
    /// Production [`Self::new`] remains HTTPS-only with TLS verification on.
    /// Redirects stay disabled. Non-loopback `http://` targets are refused.
    pub fn loopback_http_for_tests() -> Self {
        Self {
            tls_verify: false,
            follow_redirects: false,
            https_only: false,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            loopback_http_tests: true,
        }
    }

    /// Copy timeouts and response bound from a discovery spec.
    pub fn from_timeouts(timeouts: DiscoveryTimeouts, max_response_bytes: usize) -> Self {
        let mut cfg = Self::new();
        cfg.connect_timeout = timeouts.connect;
        cfg.request_timeout = timeouts.request;
        cfg.max_response_bytes = max_response_bytes;
        cfg
    }

    /// Copy timeouts and response bound onto this config.
    pub fn with_timeouts(mut self, timeouts: DiscoveryTimeouts, max_response_bytes: usize) -> Self {
        self.connect_timeout = timeouts.connect;
        self.request_timeout = timeouts.request;
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// TLS certificate verification is required.
    pub const fn tls_verify(&self) -> bool {
        self.tls_verify
    }

    /// Redirect following is disabled.
    pub const fn follow_redirects(&self) -> bool {
        self.follow_redirects
    }

    /// Non-HTTPS URLs are refused.
    pub const fn https_only(&self) -> bool {
        self.https_only
    }

    /// Bounded connect timeout applied to the HTTP client.
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Bounded request timeout applied to the HTTP client.
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Bounded response size applied after mapping list/discover payloads.
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Parse and accept an explicit HTTP URL.
    ///
    /// Credentials, query strings, and fragments are refused. `http://` is
    /// refused because TLS is required; there is no insecure downgrade path.
    pub fn validate_url(&self, raw: &str) -> Result<String, AdapterError> {
        if raw.trim().is_empty() {
            return Err(AdapterError::invalid_target("empty-url"));
        }
        let parsed =
            reqwest::Url::parse(raw).map_err(|_| AdapterError::invalid_target("url-parse"))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(AdapterError::invalid_target("credentials-in-url"));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(AdapterError::invalid_target("url-query-or-fragment"));
        }
        match parsed.scheme() {
            "https" => {}
            "http" => {
                if self.loopback_http_tests {
                    let host = parsed.host_str().unwrap_or_default();
                    if !is_loopback_host(host) {
                        return Err(AdapterError::invalid_target("non-loopback-http"));
                    }
                } else if self.https_only || self.tls_verify {
                    return Err(AdapterError::TlsRequired);
                } else {
                    return Err(AdapterError::invalid_target("unsupported-scheme"));
                }
            }
            _ => return Err(AdapterError::invalid_target("unsupported-scheme")),
        }
        if parsed.host_str().is_none() {
            return Err(AdapterError::invalid_target("missing-host"));
        }
        Ok(parsed.to_string())
    }

    /// Build a reqwest client with redirects disabled and TLS verification on.
    pub fn build_reqwest_client(&self) -> Result<reqwest::Client, AdapterError> {
        if self.follow_redirects {
            return Err(AdapterError::transport("insecure-http-config"));
        }
        if self.loopback_http_tests {
            return reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .https_only(false)
                .connect_timeout(self.connect_timeout)
                .timeout(self.request_timeout)
                .pool_max_idle_per_host(0)
                .build()
                .map_err(|_| AdapterError::transport("http-client-build"));
        }
        if !self.tls_verify || !self.https_only {
            return Err(AdapterError::transport("insecure-http-config"));
        }
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| AdapterError::transport("http-client-build"))
    }
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLANTED: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

    #[test]
    fn defaults_require_tls_and_disable_redirects() {
        let cfg = HttpTransportConfig::new();
        assert!(cfg.tls_verify());
        assert!(!cfg.follow_redirects());
        assert!(cfg.https_only());
        assert_eq!(cfg.connect_timeout(), Duration::from_secs(5));
        assert_eq!(cfg.request_timeout(), Duration::from_secs(15));
    }

    #[test]
    fn https_url_is_accepted() {
        let cfg = HttpTransportConfig::new();
        let url = cfg
            .validate_url("https://mcp.example.test/mcp")
            .expect("https url");
        assert_eq!(url, "https://mcp.example.test/mcp");
    }

    #[test]
    fn http_url_is_refused_because_tls_is_required() {
        let cfg = HttpTransportConfig::new();
        let err = cfg
            .validate_url("http://mcp.example.test/mcp")
            .expect_err("http");
        assert_eq!(err, AdapterError::TlsRequired);
        assert!(!err.to_string().contains("mcp.example.test"));
    }

    #[test]
    fn credentials_in_url_are_refused_without_echo() {
        let cfg = HttpTransportConfig::new();
        let raw = format!("https://user:{PLANTED}@mcp.example.test/mcp");
        let err = cfg.validate_url(&raw).expect_err("credentials");
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(!display.contains(PLANTED));
        assert!(!debug.contains(PLANTED));
        assert!(!display.contains("user:"));
    }

    #[test]
    fn query_and_fragment_are_refused() {
        let cfg = HttpTransportConfig::new();
        assert!(cfg
            .validate_url("https://mcp.example.test/mcp?token=x")
            .is_err());
        assert!(cfg
            .validate_url("https://mcp.example.test/mcp#frag")
            .is_err());
    }

    #[test]
    fn timeouts_from_spec_are_applied_to_builder_config() {
        let timeouts = DiscoveryTimeouts {
            connect: Duration::from_millis(11),
            request: Duration::from_millis(22),
            overall: Duration::from_millis(33),
        };
        let cfg = HttpTransportConfig::from_timeouts(timeouts, 64);
        assert_eq!(cfg.connect_timeout(), Duration::from_millis(11));
        assert_eq!(cfg.request_timeout(), Duration::from_millis(22));
        assert_eq!(cfg.max_response_bytes(), 64);
    }

    #[test]
    fn production_defaults_still_refuse_loopback_http() {
        let cfg = HttpTransportConfig::new();
        let err = cfg
            .validate_url("http://127.0.0.1:9/mcp")
            .expect_err("loopback http");
        assert_eq!(err, AdapterError::TlsRequired);
    }

    #[test]
    fn loopback_test_config_accepts_cleartext_loopback_only() {
        let cfg = HttpTransportConfig::loopback_http_for_tests();
        assert!(!cfg.https_only());
        assert!(!cfg.tls_verify());
        assert!(!cfg.follow_redirects());
        let url = cfg
            .validate_url("http://127.0.0.1:9/mcp")
            .expect("loopback http");
        assert_eq!(url, "http://127.0.0.1:9/mcp");
        assert!(cfg.validate_url("http://example.test/mcp").is_err());
        cfg.build_reqwest_client()
            .expect("loopback test client must build");
    }
}
