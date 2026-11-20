// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Deterministic payload fixtures for streaming tests.

/// A reproducible payload that can be generated and checked in bounded pieces.
#[derive(Clone, Debug)]
pub struct PayloadSpec {
    /// Payload length in bytes.
    length: u64,
    /// Byte generation scheme.
    pattern: Pattern,
    /// Optional deliberate replacement at an absolute offset.
    fault: Option<(u64, u8)>,
}

/// Supported payload generation schemes.
#[derive(Clone, Debug)]
enum Pattern {
    /// Offset-dependent binary bytes.
    Binary(u64),
    /// Literal framing around a repeated byte.
    Padded {
        /// Literal bytes before the padding.
        prefix: Vec<u8>,
        /// Literal bytes after the padding.
        suffix: Vec<u8>,
        /// Repeated byte between the literals.
        fill: u8,
    },
}

impl PayloadSpec {
    /// Create a deterministic binary payload of exactly `length` bytes.
    #[must_use]
    pub fn binary(length: u64, seed: u64) -> Self {
        Self {
            length,
            pattern: Pattern::Binary(seed),
            fault: None,
        }
    }

    /// Create a fixed-length payload with a caller-provided prefix and suffix.
    ///
    /// This can construct JSON fixtures by placing JSON punctuation in the
    /// literals and using an ASCII padding byte inside a string value.
    /// Returns `None` if the literals do not fit within `length`.
    #[must_use]
    pub fn padded(length: u64, prefix: &[u8], suffix: &[u8], fill: u8) -> Option<Self> {
        let literals = u64::try_from(prefix.len().checked_add(suffix.len())?).ok()?;
        (literals <= length).then(|| Self {
            length,
            pattern: Pattern::Padded {
                prefix: prefix.to_vec(),
                suffix: suffix.to_vec(),
                fill,
            },
            fault: None,
        })
    }

    /// Replace one byte for deliberately malformed or mismatched fixtures.
    /// Returns `None` when `offset` is outside the payload.
    #[must_use]
    pub fn with_fault(mut self, offset: u64, value: u8) -> Option<Self> {
        if offset >= self.length {
            return None;
        }
        self.fault = Some((offset, value));
        Some(self)
    }

    /// Generate up to `max_len` bytes beginning at `offset`.
    #[must_use]
    pub fn chunk(&self, offset: u64, max_len: usize) -> Vec<u8> {
        let available = self.length.saturating_sub(offset);
        let count = usize::try_from(available).unwrap_or(usize::MAX).min(max_len);
        (0..count).map(|index| self.byte(offset + index as u64)).collect()
    }

    /// Number of bytes in the fixture.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Whether the fixture has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Return the first mismatched or out-of-range absolute offset, if any.
    #[must_use]
    pub fn mismatch(&self, offset: u64, bytes: &[u8]) -> Option<u64> {
        bytes.iter().enumerate().find_map(|(index, actual)| {
            let Some(position) = offset.checked_add(index as u64) else {
                return Some(u64::MAX);
            };
            (position >= self.length || self.byte(position) != *actual).then_some(position)
        })
    }

    /// Compute the byte at a known-valid offset.
    fn byte(&self, offset: u64) -> u8 {
        if let Some((fault_offset, value)) = self.fault
            && offset == fault_offset
        {
            return value;
        }
        match &self.pattern {
            Pattern::Binary(seed) => {
                // SplitMix64 supplies reproducible offset-dependent bytes; it
                // is test data, not a cryptographic random-number generator.
                let mut value = offset.wrapping_add(*seed).wrapping_add(0x9E37_79B9_7F4A_7C15);
                value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                (value ^ (value >> 31)).to_le_bytes()[0]
            },
            Pattern::Padded { prefix, suffix, fill } => {
                if let Ok(index) = usize::try_from(offset)
                    && let Some(value) = prefix.get(index)
                {
                    return *value;
                }
                let suffix_start = self.length - suffix.len() as u64;
                if offset >= suffix_start {
                    let index = usize::try_from(offset - suffix_start).expect("suffix offset fits its allocation");
                    return suffix[index];
                }
                *fill
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadSpec;

    #[test]
    fn binary_chunks_are_independent_of_split_and_report_faults() {
        let spec = PayloadSpec::binary(257, 42);
        let all = spec.chunk(0, 300);
        let mut split = Vec::new();
        for offset in (0..257).step_by(7) {
            split.extend(spec.chunk(offset, 7));
        }
        assert_eq!(all, split);
        assert_eq!(spec.mismatch(0, &all), None);
        let faulty = spec.clone().with_fault(123, all[123] ^ 1).unwrap();
        assert_eq!(faulty.mismatch(0, &all), Some(123));
        assert_eq!(spec.mismatch(257, &[0]), Some(257));
        assert!(spec.chunk(257, 1).is_empty());
    }

    #[test]
    fn padded_json_has_exact_length_and_tail_selector() {
        let spec = PayloadSpec::padded(128, br#"{"padding":""#, br#"","route":"blue"}"#, b'x').unwrap();
        let bytes = spec.chunk(0, 128);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(bytes.len(), 128);
        assert!(text.starts_with(r#"{"padding":""#));
        assert!(text.ends_with(r#"","route":"blue"}"#));
        assert!(PayloadSpec::padded(1, b"{}", b"x", b' ').is_none());
    }
}
