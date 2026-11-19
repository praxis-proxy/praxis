// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Compact JSON sizing and bounded serialization for built-in and external filters.

use std::io;

use serde::Serialize;

/// Failure to size or serialize compact JSON.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonSizeError {
    /// The serialized representation exceeds the caller's inclusive byte limit.
    #[error("serialized JSON exceeds the byte limit")]
    LimitExceeded,
    /// The serialized length cannot be represented by `usize`.
    #[error("serialized JSON length overflow")]
    LengthOverflow,
    /// The value's serializer failed.
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
}

/// Measure the exact compact JSON byte length without retaining output.
///
/// # Examples
/// ```
/// use praxis_filter::json_size::serialized_len;
/// assert_eq!(serialized_len("é")?, 4);
/// # Ok::<(), praxis_filter::json_size::JsonSizeError>(())
/// ```
///
/// # Errors
/// Returns a serialization error or length overflow.
pub fn serialized_len<Value: Serialize + ?Sized>(value: &Value) -> Result<usize, JsonSizeError> {
    measure(value, None)
}

/// Measure compact JSON length, stopping when the inclusive limit is exceeded.
///
/// # Examples
/// ```
/// use praxis_filter::json_size::{JsonSizeError, serialized_len_capped};
/// assert_eq!(serialized_len_capped("é", 4)?, 4);
/// assert!(matches!(
///     serialized_len_capped("é", 3),
///     Err(JsonSizeError::LimitExceeded)
/// ));
/// # Ok::<(), JsonSizeError>(())
/// ```
///
/// # Errors
/// Returns limit exhaustion, length overflow, or a serialization error.
pub fn serialized_len_capped<Value: Serialize + ?Sized>(value: &Value, limit: usize) -> Result<usize, JsonSizeError> {
    measure(value, Some(limit))
}

/// Serialize compact JSON in one pass with an inclusive byte limit.
///
/// The retained output length never exceeds `limit`. A write that would exceed
/// it is rejected in full, and partial output is discarded on any error.
/// Buffer capacity may exceed the limit due to `Vec` growth and allocator
/// rounding; this is not a strict heap budget. Allocations made by a custom
/// `Serialize` implementation are outside this guarantee.
///
/// # Examples
/// ```
/// use praxis_filter::json_size::to_vec_capped;
/// assert_eq!(to_vec_capped(&[1, 2][..], 5)?, b"[1,2]");
/// # Ok::<(), praxis_filter::json_size::JsonSizeError>(())
/// ```
///
/// # Errors
/// Returns limit exhaustion, length overflow, or a serialization error.
pub fn to_vec_capped<Value: Serialize + ?Sized>(value: &Value, limit: usize) -> Result<Vec<u8>, JsonSizeError> {
    let mut writer = JsonWriter::new(Some(limit), Some(Vec::new()));
    let result = serde_json::to_writer(&mut writer, value);
    writer.finish(result)?;
    Ok(writer.output.take().unwrap_or_default())
}

/// Measure with an optional inclusive cap.
fn measure<Value: Serialize + ?Sized>(value: &Value, limit: Option<usize>) -> Result<usize, JsonSizeError> {
    let mut writer = JsonWriter::new(limit, None);
    let result = serde_json::to_writer(&mut writer, value);
    writer.finish(result)?;
    Ok(writer.length)
}

/// A counting sink with optional retained output and sticky resource failure.
struct JsonWriter {
    /// First resource failure, preserved independently of serde's error wrapping.
    failure: Option<JsonSizeError>,
    /// Number of accepted bytes.
    length: usize,
    /// Inclusive byte limit, when bounded.
    limit: Option<usize>,
    /// Output destination, absent for measurement.
    output: Option<Vec<u8>>,
}

impl JsonWriter {
    /// Create an empty sink.
    fn new(limit: Option<usize>, output: Option<Vec<u8>>) -> Self {
        Self {
            failure: None,
            length: 0,
            limit,
            output,
        }
    }

    /// Preserve resource errors even if a custom serializer replaces the IO error.
    fn finish(&mut self, result: serde_json::Result<()>) -> Result<(), JsonSizeError> {
        match self.failure.take() {
            Some(failure) => Err(failure),
            None => result.map_err(JsonSizeError::Serialization),
        }
    }

    /// Validate the next length without wrapping or crossing the limit.
    fn next_length(&self, additional: usize) -> Result<usize, JsonSizeError> {
        let length = self
            .length
            .checked_add(additional)
            .ok_or(JsonSizeError::LengthOverflow)?;
        if self.limit.is_some_and(|limit| length > limit) {
            return Err(JsonSizeError::LimitExceeded);
        }
        Ok(length)
    }
}

impl io::Write for JsonWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() {
            return Err(io::Error::other("JSON size exhausted"));
        }
        match self.next_length(buf.len()) {
            Ok(length) => {
                if let Some(output) = &mut self.output {
                    output.extend_from_slice(buf);
                }
                self.length = length;
                Ok(buf.len())
            },
            Err(failure) => {
                self.failure = Some(failure);
                Err(io::Error::other("JSON size exhausted"))
            },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn zero_limit_accepts_only_empty_writes() -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = JsonWriter::new(Some(0), Some(Vec::new()));
        writer.write_all(b"")?;
        writer.flush()?;
        writer.finish(Ok(()))?;
        assert_eq!(writer.length, 0);
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.output, Some(Vec::new()));
        Ok(())
    }

    #[test]
    fn overflow_is_distinct_and_rejects_output() {
        let mut writer = JsonWriter::new(None, Some(Vec::new()));
        writer.length = usize::MAX;
        assert!(writer.write_all(b"x").is_err());
        assert!(matches!(writer.finish(Ok(())), Err(JsonSizeError::LengthOverflow)));
        assert_eq!(writer.output, Some(Vec::new()));
    }

    #[test]
    fn failed_write_never_retains_oversized_chunk() -> io::Result<()> {
        let mut writer = JsonWriter::new(Some(3), Some(Vec::new()));
        writer.write_all(b"ab")?;
        assert!(writer.write_all(b"cd").is_err());
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.length, 2);
        assert_eq!(writer.output, Some(b"ab".to_vec()));
        assert!(matches!(writer.finish(Ok(())), Err(JsonSizeError::LimitExceeded)));
        Ok(())
    }
}
