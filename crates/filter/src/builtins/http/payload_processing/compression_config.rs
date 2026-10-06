// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Compression configuration shared between the compression filter and the protocol handler.

// -----------------------------------------------------------------------------
// Compression Constants
// -----------------------------------------------------------------------------

/// Default minimum body size in bytes below which compression is skipped.
pub(crate) const DEFAULT_MIN_SIZE_BYTES: usize = 256;

/// Default compression level (applied to all algorithms unless overridden).
pub(crate) const DEFAULT_LEVEL: u32 = 6;

/// Default MIME type patterns that qualify for compression.
pub(crate) const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/wasm",
];

/// Media types that are never compressed, regardless of `content_types`.
///
/// Encoders hold output until their internal block fills or the stream
/// ends, which would stall Server-Sent Events delivery.
const NEVER_COMPRESS_TYPES: &[&str] = &["text/event-stream"];

// -----------------------------------------------------------------------------
// CompressionConfig
// -----------------------------------------------------------------------------

/// Compression settings extracted from the filter for use by the
/// protocol handler when registering Pingora's compression module.
///
/// # Example
///
/// ```
/// use praxis_filter::CompressionConfig;
///
/// let config = CompressionConfig::default();
/// assert_eq!(config.default_level, 6);
/// assert_eq!(config.min_size_bytes, 256);
/// assert!(config.gzip_enabled);
/// assert!(config.brotli_enabled);
/// assert!(config.zstd_enabled);
/// ```
#[expect(clippy::struct_excessive_bools, reason = "algorithm flags")]
#[derive(Clone, Debug)]
pub struct CompressionConfig {
    /// Default compression level for all algorithms.
    pub default_level: u32,

    /// Whether gzip is enabled.
    pub gzip_enabled: bool,

    /// Gzip-specific compression level (overrides default).
    pub gzip_level: Option<u32>,

    /// Whether brotli is enabled.
    pub brotli_enabled: bool,

    /// Brotli-specific compression level (overrides default).
    pub brotli_level: Option<u32>,

    /// Whether zstd is enabled.
    pub zstd_enabled: bool,

    /// Zstd-specific compression level (overrides default).
    pub zstd_level: Option<u32>,

    /// Minimum response body size in bytes; smaller responses
    /// are not compressed.
    pub min_size_bytes: usize,

    /// MIME type prefixes/values that qualify for compression.
    /// A response whose `Content-Type` starts with any entry
    /// in this list is eligible.
    pub content_types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            default_level: DEFAULT_LEVEL,
            gzip_enabled: true,
            gzip_level: None,
            brotli_enabled: true,
            brotli_level: None,
            zstd_enabled: true,
            zstd_level: None,
            min_size_bytes: DEFAULT_MIN_SIZE_BYTES,
            content_types: DEFAULT_CONTENT_TYPES.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

impl CompressionConfig {
    /// Returns `true` if the given `Content-Type` value matches the
    /// configured allowlist.
    ///
    /// ```
    /// use praxis_filter::CompressionConfig;
    ///
    /// let config = CompressionConfig::default();
    /// assert!(config.matches_content_type("text/html; charset=utf-8"));
    /// assert!(config.matches_content_type("application/json"));
    /// assert!(!config.matches_content_type("image/png"));
    /// ```
    pub fn matches_content_type(&self, content_type: &str) -> bool {
        // Case-insensitive prefix compare against the raw value: the old
        // shape lowercased the whole Content-Type (an allocation and a
        // full copy) per response for the same verdicts.
        self.content_types.iter().any(|pattern| {
            content_type
                .get(..pattern.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(pattern))
                && (pattern.ends_with('/')
                    || !content_type
                        .as_bytes()
                        .get(pattern.len())
                        .is_some_and(u8::is_ascii_alphanumeric))
        })
    }

    /// Returns `true` if the response body is large enough to warrant
    /// compression, based on the `Content-Length` header value.
    ///
    /// When `Content-Length` is absent, returns `true` (compress by
    /// default for chunked/streaming responses).
    ///
    /// ```
    /// use praxis_filter::CompressionConfig;
    ///
    /// let config = CompressionConfig::default();
    /// assert!(!config.exceeds_min_size(Some(100)));
    /// assert!(config.exceeds_min_size(Some(1024)));
    /// assert!(config.exceeds_min_size(None));
    /// ```
    pub fn exceeds_min_size(&self, content_length: Option<usize>) -> bool {
        content_length.is_none_or(|len| len >= self.min_size_bytes)
    }

    /// Returns `true` if the response already has a `Content-Encoding`
    /// header, indicating it is pre-compressed.
    ///
    /// ```
    /// use http::HeaderMap;
    /// use praxis_filter::CompressionConfig;
    ///
    /// let config = CompressionConfig::default();
    ///
    /// let empty = HeaderMap::new();
    /// assert!(!config.is_already_compressed(&empty));
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("content-encoding", "gzip".parse().unwrap());
    /// assert!(config.is_already_compressed(&headers));
    /// ```
    #[expect(clippy::unused_self, reason = "method API preferred")]
    pub fn is_already_compressed(&self, headers: &http::HeaderMap) -> bool {
        headers.contains_key(http::header::CONTENT_ENCODING)
    }

    /// Returns `true` if compression should be applied to this
    /// response based on Content-Type, Content-Length, and existing
    /// Content-Encoding.
    ///
    /// Responses are never compressed when they are Server-Sent Events
    /// (`text/event-stream`), carry `Cache-Control: no-transform`
    /// ([RFC 9111 Section 5.2.2.6]), or are partial content with a
    /// `Content-Range` header ([RFC 9110 Section 14.4]).
    ///
    /// [RFC 9111 Section 5.2.2.6]: https://datatracker.ietf.org/doc/html/rfc9111#section-5.2.2.6
    /// [RFC 9110 Section 14.4]: https://datatracker.ietf.org/doc/html/rfc9110#section-14.4
    ///
    /// ```
    /// use http::HeaderMap;
    /// use praxis_filter::CompressionConfig;
    ///
    /// let config = CompressionConfig::default();
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("content-type", "text/html".parse().unwrap());
    /// headers.insert("content-length", "1024".parse().unwrap());
    /// assert!(config.should_compress(&headers));
    ///
    /// let mut small = HeaderMap::new();
    /// small.insert("content-type", "text/html".parse().unwrap());
    /// small.insert("content-length", "10".parse().unwrap());
    /// assert!(!config.should_compress(&small));
    /// ```
    pub fn should_compress(&self, headers: &http::HeaderMap) -> bool {
        if self.is_already_compressed(headers) || is_partial_content(headers) || has_no_transform(headers) {
            return false;
        }

        if !headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| !is_never_compressed_type(ct) && self.matches_content_type(ct))
        {
            return false;
        }

        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        self.exceeds_min_size(content_length)
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Returns `true` if the Content-Type media type is in
/// [`NEVER_COMPRESS_TYPES`].
fn is_never_compressed_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|media| NEVER_COMPRESS_TYPES.iter().any(|t| media.eq_ignore_ascii_case(t)))
}

/// Returns `true` if any `Cache-Control` directive is `no-transform`.
fn has_no_transform(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| d.trim().eq_ignore_ascii_case("no-transform"))
}

/// Returns `true` if the response is a byte range (`Content-Range`).
fn is_partial_content(headers: &http::HeaderMap) -> bool {
    headers.contains_key(http::header::CONTENT_RANGE)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn config_default_values() {
        let config = CompressionConfig::default();
        assert_eq!(config.default_level, 6, "default level should be 6");
        assert!(config.gzip_enabled, "gzip should be enabled by default");
        assert!(config.brotli_enabled, "brotli should be enabled by default");
        assert!(config.zstd_enabled, "zstd should be enabled by default");
        assert_eq!(config.min_size_bytes, 256, "default min_size should be 256");
        assert_eq!(config.content_types.len(), 5, "default should have 5 content types");
    }

    #[test]
    fn matches_text_content_types() {
        let config = CompressionConfig::default();
        assert!(config.matches_content_type("text/html"), "text/html should match");
        assert!(config.matches_content_type("text/plain"), "text/plain should match");
        assert!(
            config.matches_content_type("text/css; charset=utf-8"),
            "text/css should match"
        );
    }

    #[test]
    fn matches_application_types() {
        let config = CompressionConfig::default();
        assert!(
            config.matches_content_type("application/json"),
            "application/json should match"
        );
        assert!(
            config.matches_content_type("application/javascript"),
            "application/javascript should match"
        );
        assert!(
            config.matches_content_type("application/xml"),
            "application/xml should match"
        );
        assert!(
            config.matches_content_type("application/wasm"),
            "application/wasm should match"
        );
    }

    #[test]
    fn rejects_non_matching_types() {
        let config = CompressionConfig::default();
        assert!(!config.matches_content_type("image/png"), "image/png should not match");
        assert!(
            !config.matches_content_type("audio/mpeg"),
            "audio/mpeg should not match"
        );
        assert!(!config.matches_content_type("video/mp4"), "video/mp4 should not match");
    }

    #[test]
    fn case_insensitive_content_type() {
        let config = CompressionConfig::default();
        assert!(
            config.matches_content_type("Text/HTML"),
            "content type matching should be case-insensitive"
        );
        assert!(
            config.matches_content_type("APPLICATION/JSON"),
            "content type matching should be case-insensitive"
        );
    }

    #[test]
    fn exceeds_min_size_with_large_body() {
        let config = CompressionConfig::default();
        assert!(
            config.exceeds_min_size(Some(1024)),
            "1024 bytes should exceed default min_size of 256"
        );
    }

    #[test]
    fn does_not_exceed_min_size_with_small_body() {
        let config = CompressionConfig::default();
        assert!(
            !config.exceeds_min_size(Some(100)),
            "100 bytes should not exceed default min_size of 256"
        );
    }

    #[test]
    fn exceeds_min_size_unknown_length() {
        let config = CompressionConfig::default();
        assert!(
            config.exceeds_min_size(None),
            "unknown Content-Length should be treated as compressible"
        );
    }

    #[test]
    fn boundary_min_size_exact() {
        let config = CompressionConfig {
            min_size_bytes: 256,
            ..Default::default()
        };
        assert!(
            config.exceeds_min_size(Some(256)),
            "exactly min_size should qualify for compression"
        );
        assert!(
            !config.exceeds_min_size(Some(255)),
            "one below min_size should not qualify"
        );
    }

    #[test]
    fn custom_min_size() {
        let config = CompressionConfig {
            min_size_bytes: 1024,
            ..Default::default()
        };
        assert!(
            !config.exceeds_min_size(Some(512)),
            "512 bytes should not exceed custom 1024 min_size"
        );
        assert!(
            config.exceeds_min_size(Some(2048)),
            "2048 bytes should exceed custom 1024 min_size"
        );
    }

    #[test]
    fn should_compress_full_check() {
        let config = CompressionConfig::default();

        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/html".parse().unwrap());
        headers.insert(http::header::CONTENT_LENGTH, "1024".parse().unwrap());
        assert!(config.should_compress(&headers), "text/html 1024 bytes should compress");

        headers.insert(http::header::CONTENT_LENGTH, "10".parse().unwrap());
        assert!(
            !config.should_compress(&headers),
            "text/html 10 bytes should not compress"
        );
    }

    #[test]
    fn should_not_compress_missing_content_type() {
        let config = CompressionConfig::default();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "1024".parse().unwrap());
        assert!(
            !config.should_compress(&headers),
            "missing Content-Type should not compress"
        );
    }

    #[test]
    fn already_compressed_detected() {
        let config = CompressionConfig::default();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "br".parse().unwrap());
        assert!(
            config.is_already_compressed(&headers),
            "Content-Encoding: br should be detected as compressed"
        );
    }

    #[test]
    fn should_compress_chunked_response() {
        let config = CompressionConfig::default();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(
            config.should_compress(&headers),
            "chunked response with compressible type should compress"
        );
    }

    #[test]
    fn should_not_compress_event_stream() -> Result<(), Box<dyn std::error::Error>> {
        let config = CompressionConfig::default();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/event-stream; charset=utf-8".parse()?);
        assert!(!config.should_compress(&headers), "SSE should never be compressed");
        Ok(())
    }

    #[test]
    fn should_not_compress_event_stream_when_listed() -> Result<(), Box<dyn std::error::Error>> {
        let config = CompressionConfig {
            content_types: vec!["text/event-stream".to_owned()],
            ..CompressionConfig::default()
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "Text/Event-Stream".parse()?);
        assert!(
            !config.should_compress(&headers),
            "explicit content_types must not re-enable SSE compression"
        );
        Ok(())
    }

    #[test]
    fn should_not_compress_no_transform() -> Result<(), Box<dyn std::error::Error>> {
        let config = CompressionConfig::default();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/html".parse()?);
        headers.insert(http::header::CONTENT_LENGTH, "1024".parse()?);
        headers.insert(http::header::CACHE_CONTROL, "public, No-Transform".parse()?);
        assert!(
            !config.should_compress(&headers),
            "Cache-Control no-transform should disable compression"
        );
        Ok(())
    }

    #[test]
    fn should_not_compress_partial_content() -> Result<(), Box<dyn std::error::Error>> {
        let config = CompressionConfig::default();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/plain".parse()?);
        headers.insert(http::header::CONTENT_LENGTH, "2048".parse()?);
        headers.insert(http::header::CONTENT_RANGE, "bytes 0-2047/10000".parse()?);
        assert!(
            !config.should_compress(&headers),
            "Content-Range responses should not be compressed"
        );
        Ok(())
    }
}
