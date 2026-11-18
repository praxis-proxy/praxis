// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Public JSON sizing contracts, including bounded heap use.

#[cfg(test)]
mod tests {

    use std::cell::Cell;

    use praxis_filter::json_size::{JsonSizeError, serialized_len, serialized_len_capped, to_vec_capped};
    use proptest::prelude::*;
    use serde::ser::{Serialize, SerializeSeq as _, Serializer};

    #[test]
    fn compact_output_matches_serde_json() -> Result<(), JsonSizeError> {
        let record = Borrowed {
            zebra: "é🦀\n\t\"\\\u{0000}",
            alpha: &[0, 255],
        };
        let expected = serde_json::to_vec(&record)?;
        assert_eq!(to_vec_capped(&record, expected.len())?, expected);
        assert_eq!(serialized_len(&record)?, expected.len());
        assert_eq!(serialized_len_capped(&record, expected.len())?, expected.len());
        assert!(matches!(
            to_vec_capped(&record, expected.len().saturating_sub(1)),
            Err(JsonSizeError::LimitExceeded)
        ));
        assert_eq!(to_vec_capped("é", 4)?, b"\"\xc3\xa9\"");
        assert_eq!(serialized_len(&[1, 2][..])?, 5);
        assert_eq!(to_vec_capped(&[1, 2][..], 5)?, b"[1,2]");
        assert!(matches!(
            serialized_len_capped(&(), 0),
            Err(JsonSizeError::LimitExceeded)
        ));
        assert!(matches!(to_vec_capped(&(), 0), Err(JsonSizeError::LimitExceeded)));
        assert_eq!(serialized_len(&())?, 4);
        Ok(())
    }

    #[test]
    fn capped_operations_stop_early() -> Result<(), JsonSizeError> {
        let visited = Cell::new(0);
        let sequence = Sequence { visited: &visited };
        assert!(matches!(
            serialized_len_capped(&sequence, 3),
            Err(JsonSizeError::LimitExceeded)
        ));
        assert_eq!(visited.get(), 2);
        visited.set(0);
        assert!(matches!(to_vec_capped(&sequence, 3), Err(JsonSizeError::LimitExceeded)));
        assert_eq!(visited.get(), 2);
        assert_eq!(to_vec_capped(&[0], 3)?, b"[0]");
        visited.set(0);
        assert_eq!(to_vec_capped(&sequence, 2001)?.len(), 2001);
        assert_eq!(visited.get(), 1000, "successful serialization visits each element once");
        Ok(())
    }

    #[test]
    fn serialization_failures_are_distinct() {
        assert!(matches!(serialized_len(&Failure), Err(JsonSizeError::Serialization(_))));
        assert!(matches!(
            serialized_len_capped(&Failure, 100),
            Err(JsonSizeError::Serialization(_))
        ));
        assert!(matches!(
            to_vec_capped(&Failure, 100),
            Err(JsonSizeError::Serialization(_))
        ));
    }

    proptest! {
        #[test]
        fn compact_string_size_matches_serde(value in any::<String>(), limit in 0_usize..512) {
            let expected = serde_json::to_vec(&value)?;
            prop_assert_eq!(serialized_len(value.as_str())?, expected.len());
            if expected.len() <= limit {
                prop_assert_eq!(serialized_len_capped(value.as_str(), limit)?, expected.len());
                prop_assert_eq!(to_vec_capped(value.as_str(), limit)?, expected);
            } else {
                let measured = serialized_len_capped(value.as_str(), limit);
                let serialized = to_vec_capped(value.as_str(), limit);
                prop_assert!(matches!(measured, Err(JsonSizeError::LimitExceeded)));
                prop_assert!(matches!(serialized, Err(JsonSizeError::LimitExceeded)));
            }
        }
    }

    /// Borrowing and declared field order must be preserved.
    #[derive(serde::Serialize)]
    struct Borrowed<'value> {
        /// Deliberately precedes alpha.
        zebra: &'value str,
        /// Borrowed slice.
        alpha: &'value [u8],
    }

    /// A sequence that records how many elements are visited.
    struct Sequence<'value> {
        /// Element visit count.
        visited: &'value Cell<usize>,
    }

    impl Serialize for Sequence<'_> {
        fn serialize<Output: Serializer>(&self, serializer: Output) -> Result<Output::Ok, Output::Error> {
            let mut sequence = serializer.serialize_seq(Some(1000))?;
            for _ in 0..1000 {
                self.visited.set(self.visited.get().saturating_add(1));
                sequence.serialize_element(&0)?;
            }
            sequence.end()
        }
    }

    /// Fails after emitting partial output.
    struct Failure;

    impl Serialize for Failure {
        fn serialize<Output: Serializer>(&self, serializer: Output) -> Result<Output::Ok, Output::Error> {
            let mut sequence = serializer.serialize_seq(None)?;
            sequence.serialize_element("partial")?;
            Err(serde::ser::Error::custom("intentional failure"))
        }
    }
}
