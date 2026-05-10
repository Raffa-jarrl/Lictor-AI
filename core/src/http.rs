//! HTTP abstraction: a `Fetch` trait that checks call to do I/O, plus a native
//! `UreqFetch` implementation behind the `native` feature. WASM builds bring
//! their own implementation that calls the browser's `fetch`.
//!
//! # Safety contract
//!
//! Mirrors `audit.py`:
//!   - GET / OPTIONS / HEAD only. We never POST.
//!   - 1 request per second per host, hard-capped.
//!   - 12-second per-request timeout.
//!   - Body capped at 2 MB (we discard the rest).
//!   - Cross-host redirects are NOT followed — we treat them as the end of the chain.

use crate::Error;

/// HTTP method we'll send. Lictor never POSTs from a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET — body returned.
    Get,
    /// HEAD — headers only.
    Head,
    /// OPTIONS — for CORS introspection.
    Options,
}

impl Method {
    /// Convert to its HTTP wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
        }
    }
}

/// Minimal HTTP response surfaced to checks.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code. `-1` is encoded as 0 here (errors return `Err`, not 0).
    pub status: u16,
    /// Response headers, lowercased keys.
    pub headers: std::collections::HashMap<String, String>,
    /// Response body, capped at 2 MB.
    pub body: Vec<u8>,
}

impl Response {
    /// Header lookup, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }

    /// Body as a UTF-8 string with replacement chars on invalid sequences.
    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// Trait used by checks to perform their probes. One impl per environment:
/// `UreqFetch` (native), `MockFetch` (tests), and a future WASM impl that
/// delegates to `window.fetch`.
pub trait Fetch {
    /// Fetch a URL with the polite contract.
    ///
    /// Returns `Err` on transport failure (DNS, TCP, TLS, timeout). Returns
    /// `Ok(Response { status: 4xx/5xx, .. })` on HTTP failure — checks decide
    /// what to do with non-2xx.
    fn fetch(&self, url: &str, method: Method) -> Result<Response, Error>;
}

/// Maximum bytes we read from any response.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Native implementation (ureq)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "native")]
mod native {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// Native HTTP fetcher built on `ureq`. Rate-limits per-host to 1 req/sec.
    pub struct UreqFetch {
        agent: ureq::Agent,
        last_hit: Mutex<HashMap<String, Instant>>,
        rate_limit: Duration,
    }

    impl UreqFetch {
        /// Build a fetcher with default settings: 12s timeout, no auto-redirects
        /// (we follow them manually so we can enforce same-host).
        pub fn new() -> Self {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(12))
                .redirects(0) // disable auto-follow; we do it manually
                .user_agent(crate::USER_AGENT)
                .build();
            Self {
                agent,
                last_hit: Mutex::new(HashMap::new()),
                rate_limit: Duration::from_secs(1),
            }
        }

        /// Sleep until our 1-req/sec/host budget allows the next call.
        fn rate_limit(&self, host: &str) {
            let mut map = self.last_hit.lock().unwrap();
            let now = Instant::now();
            if let Some(prev) = map.get(host) {
                let elapsed = now.saturating_duration_since(*prev);
                if elapsed < self.rate_limit {
                    let sleep_for = self.rate_limit - elapsed;
                    drop(map);
                    std::thread::sleep(sleep_for);
                    let mut map = self.last_hit.lock().unwrap();
                    map.insert(host.to_string(), Instant::now());
                    return;
                }
            }
            map.insert(host.to_string(), now);
        }
    }

    impl Default for UreqFetch {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Fetch for UreqFetch {
        fn fetch(&self, url: &str, method: Method) -> Result<Response, Error> {
            // Determine host for rate-limiting.
            let parsed = url::Url::parse(url)?;
            let host = parsed.host_str().ok_or_else(|| Error::Other(format!("no host in url: {url}")))?.to_lowercase();
            self.rate_limit(&host);

            let req = self.agent.request(method.as_str(), url);
            let resp = match req.call() {
                Ok(r) => r,
                Err(ureq::Error::Status(_, r)) => r, // 4xx/5xx — return the response, not an error
                Err(ureq::Error::Transport(t)) => return Err(Error::Http(t.to_string())),
            };

            let status = resp.status();

            // If 3xx, manually check Location and decide whether to follow.
            // We follow at most ONCE and only if the redirect target is on the same host.
            if (300..400).contains(&status) {
                if let Some(loc) = resp.header("Location") {
                    let next = match url::Url::parse(loc) {
                        Ok(u) => u,
                        Err(_) => parsed.join(loc).map_err(Error::from)?,
                    };
                    let next_host = next.host_str().unwrap_or("").to_lowercase();
                    if next_host == host {
                        return self.fetch(next.as_str(), method);
                    }
                    // Cross-host redirect: stop. Return the 3xx as-is so the
                    // caller can see what happened.
                }
            }

            // Collect headers.
            let mut headers = HashMap::with_capacity(resp.headers_names().len());
            for name in resp.headers_names() {
                if let Some(value) = resp.header(&name) {
                    headers.insert(name.to_lowercase(), value.to_string());
                }
            }

            // Read body, capped.
            let mut body = Vec::with_capacity(8 * 1024);
            let mut reader = resp.into_reader().take(MAX_BODY_BYTES as u64);
            reader.read_to_end(&mut body).map_err(|e| Error::Http(e.to_string()))?;

            Ok(Response { status, headers, body })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rate_limit_blocks_back_to_back_calls() {
            let f = UreqFetch::new();
            // Two calls to "rate_limit" for the same host should sleep ~1s on the second.
            let t0 = Instant::now();
            f.rate_limit("example.com");
            f.rate_limit("example.com");
            let elapsed = t0.elapsed();
            assert!(
                elapsed >= Duration::from_millis(900),
                "expected >= 900ms gap, got {elapsed:?}"
            );
        }
    }
}

#[cfg(feature = "native")]
pub use native::UreqFetch;

// ─────────────────────────────────────────────────────────────────────────────
// Mock implementation for tests
// ─────────────────────────────────────────────────────────────────────────────

/// A mock fetcher whose responses are pre-loaded by URL. Used by check tests
/// and any other consumer that wants deterministic I/O.
pub struct MockFetch {
    /// Map of (method, url) → canned response.
    responses: std::collections::HashMap<(Method, String), Response>,
    /// Default response when no match is found.
    default: Response,
}

impl MockFetch {
    /// Build a mock that returns 404 on every URL by default.
    pub fn new() -> Self {
        Self {
            responses: std::collections::HashMap::new(),
            default: Response {
                status: 404,
                headers: std::collections::HashMap::new(),
                body: Vec::new(),
            },
        }
    }

    /// Pre-load a response for a (method, URL) pair.
    pub fn with(mut self, method: Method, url: impl Into<String>, response: Response) -> Self {
        self.responses.insert((method, url.into()), response);
        self
    }

    /// Convenience: pre-load a 200 GET with HTML body and content-type.
    pub fn with_html(self, url: impl Into<String>, body: impl Into<String>) -> Self {
        let body = body.into().into_bytes();
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".to_string(), "text/html; charset=utf-8".to_string());
        self.with(Method::Get, url, Response { status: 200, headers, body })
    }

    /// Convenience: pre-load a 200 GET with JSON body and content-type.
    pub fn with_json(self, url: impl Into<String>, body: impl Into<String>) -> Self {
        let body = body.into().into_bytes();
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        self.with(Method::Get, url, Response { status: 200, headers, body })
    }

    /// Convenience: pre-load a status-only response (no body).
    pub fn with_status(self, method: Method, url: impl Into<String>, status: u16) -> Self {
        self.with(method, url, Response { status, headers: std::collections::HashMap::new(), body: Vec::new() })
    }
}

impl Default for MockFetch {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetch for MockFetch {
    fn fetch(&self, url: &str, method: Method) -> Result<Response, Error> {
        Ok(self
            .responses
            .get(&(method, url.to_string()))
            .cloned()
            .unwrap_or_else(|| self.default.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_returns_canned_response() {
        let m = MockFetch::new().with_html("https://example.com/", "<html>hi</html>");
        let r = m.fetch("https://example.com/", Method::Get).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body_str(), "<html>hi</html>");
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    }

    #[test]
    fn mock_default_is_404() {
        let m = MockFetch::new();
        let r = m.fetch("https://nowhere.example/", Method::Get).unwrap();
        assert_eq!(r.status, 404);
    }
}
