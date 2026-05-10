//! Polite, rate-limited HTTP client. Native-only — the WASM build relies on
//! the host browser's fetch API.
//!
//! Contract:
//!   - GET / OPTIONS / HEAD only. We never POST.
//!   - 1 request/sec per host hard cap.
//!   - 12-second timeout per request.
//!   - Body capped at 2 MB.
//!   - We never follow redirects to a different hostname.
//!
//! TODO(Phase 1): port from `audit.py::fetch`. Currently a stub.

use crate::Error;

/// HTTP method we'll send. Lictor never POSTs from a check.
#[derive(Debug, Clone, Copy)]
pub enum Method {
    /// GET — body returned.
    Get,
    /// HEAD — headers only.
    Head,
    /// OPTIONS — for CORS introspection.
    Options,
}

/// Minimal HTTP response we surface to checks.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response headers (lowercased keys).
    pub headers: std::collections::HashMap<String, String>,
    /// Response body (capped at 2 MB).
    pub body: Vec<u8>,
}

/// Fetch a URL with the polite contract. Stub implementation.
pub fn fetch(_url: &str, _method: Method) -> Result<Response, Error> {
    Err(Error::Other("http::fetch not yet implemented".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_errors() {
        assert!(fetch("https://example.com", Method::Get).is_err());
    }
}
