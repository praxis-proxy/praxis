// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! SQL schema generation for the response store.

use super::types::StoreError;

// -----------------------------------------------------------------------------
// Table Names
// -----------------------------------------------------------------------------

/// Resolved table names for a store instance.
///
/// Table names are configured via YAML (e.g.,
/// `openai_responses`, `google_interactions`). Each provider
/// chooses its own names.
pub(crate) struct TableNames {
    /// Responses table name.
    pub responses: String,
    /// Conversation messages table name.
    pub conversations: String,
}

// -----------------------------------------------------------------------------
// Schema DDL
// -----------------------------------------------------------------------------

/// Generate DDL statements for the given table names.
///
/// Each statement uses `IF NOT EXISTS` so it is safe to run on
/// every startup. The schema uses TEXT for JSON columns (standard
/// `SQLite` pattern) and BIGINT for timestamps so the same DDL is
/// compatible with `PostgreSQL` `i64` decoding.
///
/// # Errors
///
/// Returns [`StoreError::Database`] if table names contain
/// invalid characters.
pub(crate) fn generate_ddl(tables: &TableNames) -> Result<Vec<String>, StoreError> {
    let (r, c) = validate_table_names(tables)?;

    Ok(vec![
        format!(
            "CREATE TABLE IF NOT EXISTS {r} (
                tenant_id       TEXT NOT NULL,
                id              TEXT NOT NULL,
                created_at      BIGINT NOT NULL,
                model           TEXT NOT NULL,
                response_object TEXT NOT NULL,
                input           TEXT NOT NULL,
                messages        TEXT NOT NULL,
                PRIMARY KEY (tenant_id, id)
            )"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {c} (
                conversation_id TEXT NOT NULL,
                tenant_id       TEXT NOT NULL,
                messages        TEXT NOT NULL,
                PRIMARY KEY (conversation_id, tenant_id)
            )"
        ),
        format!("CREATE INDEX IF NOT EXISTS idx_{c}_tenant_id ON {c}(tenant_id)"),
    ])
}

/// Validate identifier lengths for `PostgreSQL` DDL.
///
/// `PostgreSQL` truncates identifiers above 63 bytes. The
/// conversation table name is also embedded in the generated tenant
/// index name, so it needs a smaller limit than table identifiers.
///
/// # Errors
///
/// Returns [`StoreError::Database`] when an identifier would exceed
/// the `PostgreSQL` limit.
pub(crate) fn validate_postgres_identifiers(tables: &TableNames) -> Result<(), StoreError> {
    let (r, c) = validate_table_names(tables)?;

    validate_postgres_identifier_len("response table name", r, POSTGRES_MAX_IDENTIFIER_LEN)?;
    validate_postgres_identifier_len("conversation table name", c, POSTGRES_MAX_CONVERSATION_TABLE_LEN)?;

    Ok(())
}

/// Validate table names for a `PostgreSQL` response store.
pub(crate) fn validate_postgres_table_identifiers(
    responses_table: &str,
    conversations_table: &str,
) -> Result<(), StoreError> {
    let tables = TableNames {
        responses: responses_table.to_owned(),
        conversations: conversations_table.to_owned(),
    };
    validate_postgres_identifiers(&tables)
}

/// Validate the configured table names and return them as borrowed identifiers.
fn validate_table_names(tables: &TableNames) -> Result<(&str, &str), StoreError> {
    let r = tables.responses.as_str();
    let c = tables.conversations.as_str();

    validate_identifier(r)?;
    validate_identifier(c)?;
    if r.eq_ignore_ascii_case(c) {
        return Err(StoreError::Database(format!(
            "response and conversation table names must be distinct: {r}"
        )));
    }
    Ok((r, c))
}

/// Maximum length for a table name identifier.
/// SQLite has no identifier length limit, but we cap table names
/// to prevent pathological DDL strings from config input.
const MAX_IDENTIFIER_LEN: usize = 128;

/// Maximum identifier length accepted by `PostgreSQL`.
const POSTGRES_MAX_IDENTIFIER_LEN: usize = 63;

/// Maximum conversation table name length that leaves room for
/// `idx_` (4) and `_tenant_id` (10) in the generated index name.
const POSTGRES_MAX_CONVERSATION_TABLE_LEN: usize = POSTGRES_MAX_IDENTIFIER_LEN - 14;

/// Reject identifiers that could cause SQL injection or invalid DDL.
pub(crate) fn validate_identifier(name: &str) -> Result<(), StoreError> {
    if name.is_empty() {
        return Err(StoreError::Database("table name must not be empty".to_owned()));
    }
    if name.len() > MAX_IDENTIFIER_LEN {
        return Err(StoreError::Database(format!(
            "table name exceeds {MAX_IDENTIFIER_LEN} characters: {name}"
        )));
    }
    if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return Err(StoreError::Database(format!(
            "table name must start with a letter or underscore: {name}"
        )));
    }
    // Hyphens are valid in quoted SQLite identifiers but we
    // interpolate table names unquoted in SQL statements, so
    // restrict to alphanumeric + underscore to avoid quoting.
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(StoreError::Database(format!(
            "table name contains invalid characters: {name}"
        )));
    }
    Ok(())
}

/// Reject a `PostgreSQL` identifier that would be truncated.
fn validate_postgres_identifier_len(kind: &str, name: &str, max_len: usize) -> Result<(), StoreError> {
    if name.len() > max_len {
        return Err(StoreError::Database(format!(
            "{kind} exceeds PostgreSQL identifier limit of {max_len} bytes: {name}"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn valid_table_name() {
        validate_identifier("openai_responses").expect("valid name should pass");
    }

    #[test]
    fn valid_name_with_underscore_prefix() {
        validate_identifier("_internal").expect("underscore prefix should pass");
    }

    #[test]
    fn reject_empty_name() {
        let err = validate_identifier("").unwrap_err();
        assert!(err.to_string().contains("empty"), "should reject empty name: {err}");
    }

    #[test]
    fn reject_name_starting_with_digit() {
        let err = validate_identifier("123responses").unwrap_err();
        assert!(
            err.to_string().contains("start with"),
            "should reject digit prefix: {err}"
        );
    }

    #[test]
    fn reject_special_characters() {
        let err = validate_identifier("drop; DROP TABLE").unwrap_err();
        assert!(
            err.to_string().contains("invalid characters"),
            "should reject special chars: {err}"
        );
    }

    #[test]
    fn reject_hyphen() {
        let err = validate_identifier("my-table").unwrap_err();
        assert!(
            err.to_string().contains("invalid characters"),
            "should reject hyphen: {err}"
        );
    }

    #[test]
    fn reject_excessively_long_name() {
        let long = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        let err = validate_identifier(&long).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "should reject long name: {err}");
    }

    #[test]
    fn generate_ddl_produces_valid_statements() {
        let tables = TableNames {
            responses: "test_responses".to_owned(),
            conversations: "test_conversations".to_owned(),
        };
        let ddl = generate_ddl(&tables).expect("valid names should produce DDL");
        assert_eq!(ddl.len(), 3, "should produce 3 DDL statements");
        assert!(
            ddl[0].contains("test_responses"),
            "first statement should reference responses table"
        );
    }

    #[test]
    fn generate_ddl_uses_bigint_for_created_at() {
        let tables = TableNames {
            responses: "test_responses".to_owned(),
            conversations: "test_conversations".to_owned(),
        };
        let ddl = generate_ddl(&tables).expect("valid names should produce DDL");

        assert!(
            ddl[0].contains("created_at      BIGINT NOT NULL"),
            "created_at should decode as i64 in Postgres: {}",
            ddl[0]
        );
    }

    #[test]
    fn generate_ddl_rejects_invalid_name() {
        let tables = TableNames {
            responses: "valid_name".to_owned(),
            conversations: "1invalid".to_owned(),
        };
        let err = generate_ddl(&tables).unwrap_err();
        assert!(
            err.to_string().contains("start with"),
            "should reject invalid conversation table name: {err}"
        );
    }

    #[test]
    fn generate_ddl_rejects_duplicate_names() {
        let tables = TableNames {
            responses: "same_table".to_owned(),
            conversations: "same_table".to_owned(),
        };
        let err = generate_ddl(&tables).unwrap_err();
        assert!(
            err.to_string().contains("distinct"),
            "should reject duplicate table names: {err}"
        );
    }

    #[test]
    fn generate_ddl_rejects_case_insensitive_duplicate_names() {
        let tables = TableNames {
            responses: "Responses".to_owned(),
            conversations: "responses".to_owned(),
        };
        let err = generate_ddl(&tables).unwrap_err();
        assert!(
            err.to_string().contains("distinct"),
            "should reject case-insensitive duplicate table names: {err}"
        );
    }

    #[test]
    fn postgres_identifier_rejects_truncated_table_name() {
        let tables = TableNames {
            responses: "r".repeat(POSTGRES_MAX_IDENTIFIER_LEN + 1),
            conversations: "test_conversations".to_owned(),
        };
        let err = validate_postgres_identifiers(&tables).unwrap_err();

        assert!(
            err.to_string().contains("PostgreSQL identifier limit"),
            "should reject names PostgreSQL would truncate: {err}"
        );
    }

    #[test]
    fn postgres_identifier_rejects_truncated_index_name() {
        let tables = TableNames {
            responses: "test_responses".to_owned(),
            conversations: "c".repeat(POSTGRES_MAX_CONVERSATION_TABLE_LEN + 1),
        };
        let err = validate_postgres_identifiers(&tables).unwrap_err();

        assert!(
            err.to_string().contains("PostgreSQL identifier limit"),
            "should reject generated index names PostgreSQL would truncate: {err}"
        );
    }
}
