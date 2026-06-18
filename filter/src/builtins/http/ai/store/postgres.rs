// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! [`PostgresResponseStore`] — `PostgreSQL` backend for the response store.

use std::path::Path;

use async_trait::async_trait;
use serde::Deserialize;
use sqlx::{
    Row as _,
    postgres::{PgConnectOptions, PgPoolOptions, PgRow, PgSslMode},
};
use tracing::info;

use super::{
    schemas::{TableNames, generate_ddl, validate_postgres_identifiers},
    trait_def::ResponseStore,
    types::{ConversationRecord, ResponseRecord, StoreError},
};

// -----------------------------------------------------------------------------
// SslMode
// -----------------------------------------------------------------------------

/// TLS mode for `PostgreSQL` connections.
///
/// Maps to [`PgSslMode`] from sqlx. Defaults to [`Prefer`] which
/// attempts TLS but falls back to plaintext if the server does not
/// support it.
///
/// [`Prefer`]: SslMode::Prefer
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SslMode {
    /// Do not use TLS.
    Disable,

    /// Attempt TLS, fall back to plaintext.
    #[default]
    Prefer,

    /// Require TLS (reject plaintext).
    Require,

    /// Require TLS and verify the server certificate chain.
    VerifyCa,

    /// Require TLS and verify both certificate chain and hostname.
    VerifyFull,
}

impl From<SslMode> for PgSslMode {
    fn from(mode: SslMode) -> Self {
        match mode {
            SslMode::Disable => Self::Disable,
            SslMode::Prefer => Self::Prefer,
            SslMode::Require => Self::Require,
            SslMode::VerifyCa => Self::VerifyCa,
            SslMode::VerifyFull => Self::VerifyFull,
        }
    }
}

// -----------------------------------------------------------------------------
// PostgresResponseStore
// -----------------------------------------------------------------------------

/// PostgreSQL-backed response store.
///
/// Uses [`sqlx::PgPool`] for async connection pooling. Table names
/// are configurable per provider (e.g., `openai_responses`,
/// `google_interactions`) to isolate data per provider.
pub struct PostgresResponseStore {
    /// Connection pool.
    pool: sqlx::PgPool,
    /// Configured table names.
    tables: TableNames,
}

impl PostgresResponseStore {
    /// Create a new store and initialize the schema.
    ///
    /// The `database_url` is a `PostgreSQL` connection string
    /// (e.g., `"postgres://user:pass@host:5432/praxis"`).
    ///
    /// `responses_table` and `conversations_table` are the SQL
    /// table names to use. These come from the filter's YAML
    /// config (e.g., `openai_responses`).
    ///
    /// `items_table`, when provided, enables the conversation items
    /// table for storing individual conversation entries.
    ///
    /// `ssl_mode`, when provided, overrides any `sslmode` in the
    /// URL. Use [`SslMode::VerifyCa`] or [`SslMode::VerifyFull`]
    /// with `ssl_root_cert` to verify the server against a custom
    /// CA. Certificate path existence is validated at connection
    /// time, not at construction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the connection, schema
    /// initialization, or table name validation fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor mirrors SqliteResponseStore::new with SSL additions"
    )]
    pub async fn new(
        database_url: &str,
        responses_table: &str,
        conversations_table: &str,
        items_table: Option<&str>,
        ssl_mode: Option<SslMode>,
        ssl_root_cert: Option<&str>,
    ) -> Result<Self, StoreError> {
        let tables = TableNames {
            responses: responses_table.to_owned(),
            conversations: conversations_table.to_owned(),
            items: items_table.map(str::to_owned),
        };
        validate_postgres_identifiers(&tables)?;
        let ddl = generate_ddl(&tables)?;

        let options = pg_connect_options(database_url, ssl_mode, ssl_root_cert)?;
        let pool = PgPoolOptions::new()
            .connect_with(options)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        for statement in &ddl {
            sqlx::query(statement)
                .execute(&pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        info!(
            responses = responses_table,
            conversations = conversations_table,
            "postgres response store initialized"
        );
        Ok(Self { pool, tables })
    }
}

/// Build `PostgreSQL` connection options from URL and optional TLS overrides.
fn pg_connect_options(
    database_url: &str,
    ssl_mode: Option<SslMode>,
    ssl_root_cert: Option<&str>,
) -> Result<PgConnectOptions, StoreError> {
    let mut options: PgConnectOptions = database_url
        .parse()
        .map_err(|e: sqlx::Error| StoreError::Database(e.to_string()))?;

    if let Some(mode) = ssl_mode {
        options = options.ssl_mode(PgSslMode::from(mode));
    }

    if let Some(cert_path) = ssl_root_cert {
        options = options.ssl_root_cert(Path::new(cert_path));
    }

    Ok(options)
}

#[async_trait]
impl ResponseStore for PostgresResponseStore {
    async fn upsert_response(&self, record: &ResponseRecord) -> Result<(), StoreError> {
        let response_object =
            serde_json::to_string(&record.response_object).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let input = serde_json::to_string(&record.input).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let messages = serde_json::to_string(&record.messages).map_err(|e| StoreError::Serialization(e.to_string()))?;

        let sql = format!(
            "INSERT INTO {} \
             (id, tenant_id, created_at, model, response_object, input, messages) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (tenant_id, id) DO UPDATE SET \
             created_at = EXCLUDED.created_at, \
             model = EXCLUDED.model, \
             response_object = EXCLUDED.response_object, \
             input = EXCLUDED.input, \
             messages = EXCLUDED.messages",
            self.tables.responses
        );

        sqlx::query(&sql)
            .bind(&record.id)
            .bind(&record.tenant_id)
            .bind(record.created_at)
            .bind(&record.model)
            .bind(&response_object)
            .bind(&input)
            .bind(&messages)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn get_response(&self, tenant_id: &str, id: &str) -> Result<Option<ResponseRecord>, StoreError> {
        let sql = format!(
            "SELECT id, tenant_id, created_at, model, \
                    response_object, input, messages \
             FROM {} \
             WHERE id = $1 AND tenant_id = $2",
            self.tables.responses
        );

        let row = sqlx::query(&sql)
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| row_to_response_record(&r)).transpose()
    }

    async fn delete_response(&self, tenant_id: &str, id: &str) -> Result<bool, StoreError> {
        let sql = format!("DELETE FROM {} WHERE id = $1 AND tenant_id = $2", self.tables.responses);

        let result = sqlx::query(&sql)
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    async fn upsert_conversation(&self, record: &ConversationRecord) -> Result<(), StoreError> {
        let messages = serde_json::to_string(&record.messages).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let metadata = serde_json::to_string(&record.metadata).map_err(|e| StoreError::Serialization(e.to_string()))?;

        let sql = format!(
            "INSERT INTO {} \
             (conversation_id, tenant_id, created_at, metadata, messages) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (conversation_id, tenant_id) DO UPDATE SET \
             messages = EXCLUDED.messages",
            self.tables.conversations
        );

        sqlx::query(&sql)
            .bind(&record.conversation_id)
            .bind(&record.tenant_id)
            .bind(record.created_at)
            .bind(&metadata)
            .bind(&messages)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn get_conversation(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationRecord>, StoreError> {
        let sql = format!(
            "SELECT conversation_id, tenant_id, created_at, \
                    metadata, messages \
             FROM {} \
             WHERE conversation_id = $1 AND tenant_id = $2",
            self.tables.conversations
        );

        let row = sqlx::query(&sql)
            .bind(conversation_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| row_to_conversation_record(&r)).transpose()
    }

    async fn delete_conversation(&self, tenant_id: &str, conversation_id: &str) -> Result<bool, StoreError> {
        let sql = format!(
            "DELETE FROM {} WHERE conversation_id = $1 AND tenant_id = $2",
            self.tables.conversations
        );

        let result = sqlx::query(&sql)
            .bind(conversation_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}

// -----------------------------------------------------------------------------
// Row Conversion
// -----------------------------------------------------------------------------

/// Convert a sqlx row to a [`ResponseRecord`].
fn row_to_response_record(row: &PgRow) -> Result<ResponseRecord, StoreError> {
    let response_object_json: String = row
        .try_get("response_object")
        .map_err(|e| StoreError::Database(e.to_string()))?;
    let input_json: String = row.try_get("input").map_err(|e| StoreError::Database(e.to_string()))?;
    let messages_json: String = row
        .try_get("messages")
        .map_err(|e| StoreError::Database(e.to_string()))?;

    Ok(ResponseRecord {
        id: row.try_get("id").map_err(|e| StoreError::Database(e.to_string()))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        model: row.try_get("model").map_err(|e| StoreError::Database(e.to_string()))?,
        response_object: serde_json::from_str(&response_object_json)
            .map_err(|e| StoreError::Serialization(e.to_string()))?,
        input: serde_json::from_str(&input_json).map_err(|e| StoreError::Serialization(e.to_string()))?,
        messages: serde_json::from_str(&messages_json).map_err(|e| StoreError::Serialization(e.to_string()))?,
    })
}

/// Convert a sqlx row to a [`ConversationRecord`].
fn row_to_conversation_record(row: &PgRow) -> Result<ConversationRecord, StoreError> {
    let messages_json: String = row
        .try_get("messages")
        .map_err(|e| StoreError::Database(e.to_string()))?;
    let metadata_json: String = row
        .try_get("metadata")
        .map_err(|e| StoreError::Database(e.to_string()))?;

    Ok(ConversationRecord {
        conversation_id: row
            .try_get("conversation_id")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        metadata: serde_json::from_str(&metadata_json).map_err(|e| StoreError::Serialization(e.to_string()))?,
        messages: serde_json::from_str(&messages_json).map_err(|e| StoreError::Serialization(e.to_string()))?,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn connect_options_preserves_url_sslmode_without_override() {
        let options = pg_connect_options("postgres://user:pass@example.com/db?sslmode=verify-full", None, None)
            .expect("URL with sslmode should parse");

        assert!(
            matches!(options.get_ssl_mode(), PgSslMode::VerifyFull),
            "URL sslmode should be preserved"
        );
    }

    #[test]
    fn connect_options_uses_explicit_sslmode_override() {
        let options = pg_connect_options(
            "postgres://user:pass@example.com/db?sslmode=verify-full",
            Some(SslMode::Disable),
            None,
        )
        .expect("URL with override should parse");

        assert!(
            matches!(options.get_ssl_mode(), PgSslMode::Disable),
            "explicit ssl_mode should override URL sslmode"
        );
    }
}
