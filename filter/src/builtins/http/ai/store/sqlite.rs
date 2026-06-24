// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! [`SqliteResponseStore`] — `SQLite` backend for the response store.

use async_trait::async_trait;
use sqlx::{
    AssertSqlSafe, Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use tracing::info;

use super::{
    schemas::{TableNames, generate_ddl},
    trait_def::{ConversationItemStore, ResponseStore},
    types::{ConversationItemRecord, ConversationRecord, ResponseRecord, StoreError},
};

// -----------------------------------------------------------------------------
// SqliteResponseStore
// -----------------------------------------------------------------------------

/// SQLite-backed response store.
///
/// Uses [`sqlx::SqlitePool`] for async connection pooling. Table
/// names are configurable per provider (e.g., `openai_responses`,
/// `google_interactions`) to isolate data per provider.
pub struct SqliteResponseStore {
    /// Connection pool.
    pool: SqlitePool,
    /// Configured table names.
    tables: TableNames,
}

impl SqliteResponseStore {
    /// Create a new store and initialize the schema.
    ///
    /// The `database_url` is a `SQLite` connection string. Use
    /// `"sqlite::memory:"` for in-memory databases (testing) or
    /// `"sqlite:///path/to/db.sqlite?mode=rwc"` for file-backed.
    ///
    /// `responses_table` and `conversations_table` are the SQL
    /// table names to use. These come from the filter's YAML
    /// config (e.g., `openai_responses`). `items_table` is
    /// optional and enables conversation item storage.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the connection, schema
    /// initialization, or table name validation fails.
    pub async fn new(
        database_url: &str,
        responses_table: &str,
        conversations_table: &str,
        items_table: Option<&str>,
    ) -> Result<Self, StoreError> {
        let tables = TableNames {
            responses: responses_table.to_owned(),
            conversations: conversations_table.to_owned(),
            items: items_table.map(str::to_owned),
        };
        let ddl = generate_ddl(&tables)?;

        let options: SqliteConnectOptions = database_url
            .parse()
            .map_err(|e: sqlx::Error| StoreError::Database(e.to_string()))?;

        let pool = sqlite_pool_options(database_url)
            .connect_with(options.create_if_missing(true))
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        for statement in &ddl {
            sqlx::query(AssertSqlSafe(statement.as_str()))
                .execute(&pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        info!(
            responses = responses_table,
            conversations = conversations_table,
            "response store initialized"
        );
        Ok(Self { pool, tables })
    }
}

/// Build pool options for the requested `SQLite` database URL.
fn sqlite_pool_options(database_url: &str) -> SqlitePoolOptions {
    if is_memory_database_url(database_url) {
        SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
    } else {
        SqlitePoolOptions::new()
    }
}

/// Return whether the database URL targets an in-memory `SQLite` database.
fn is_memory_database_url(database_url: &str) -> bool {
    let url = database_url.trim();
    if url == "sqlite::memory:" || url == "sqlite://:memory:" {
        return true;
    }
    let query = url.split_once('?').map_or("", |(_, q)| q);
    query
        .split('&')
        .any(|param| param == "mode=memory" || param.starts_with("mode=memory&"))
}

#[async_trait]
impl ResponseStore for SqliteResponseStore {
    async fn upsert_response(&self, record: &ResponseRecord) -> Result<(), StoreError> {
        let response_object =
            serde_json::to_string(&record.response_object).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let input = serde_json::to_string(&record.input).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let messages = serde_json::to_string(&record.messages).map_err(|e| StoreError::Serialization(e.to_string()))?;

        let sql = format!(
            "INSERT OR REPLACE INTO {} \
             (id, tenant_id, created_at, model, response_object, input, messages) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            self.tables.responses
        );

        sqlx::query(AssertSqlSafe(sql.as_str()))
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
             WHERE id = ? AND tenant_id = ?",
            self.tables.responses
        );

        let row = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| row_to_response_record(&r)).transpose()
    }

    async fn delete_response(&self, tenant_id: &str, id: &str) -> Result<bool, StoreError> {
        let sql = format!("DELETE FROM {} WHERE id = ? AND tenant_id = ?", self.tables.responses);

        let result = sqlx::query(AssertSqlSafe(sql.as_str()))
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
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(conversation_id, tenant_id) \
             DO UPDATE SET messages = excluded.messages",
            self.tables.conversations
        );

        sqlx::query(AssertSqlSafe(sql.as_str()))
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
            "SELECT conversation_id, tenant_id, created_at, metadata, messages \
             FROM {} \
             WHERE conversation_id = ? AND tenant_id = ?",
            self.tables.conversations
        );

        let row = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(conversation_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| row_to_conversation_record(&r)).transpose()
    }

    async fn delete_conversation(&self, tenant_id: &str, conversation_id: &str) -> Result<bool, StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if let Some(items_table) = &self.tables.items {
            let items_sql = format!("DELETE FROM {items_table} WHERE tenant_id = ? AND conversation_id = ?");
            sqlx::query(AssertSqlSafe(items_sql.as_str()))
                .bind(tenant_id)
                .bind(conversation_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        let sql = format!(
            "DELETE FROM {} WHERE conversation_id = ? AND tenant_id = ?",
            self.tables.conversations
        );

        let result = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(conversation_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.commit().await.map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "async_trait counts the store method group as one expansion"
)]
#[async_trait]
impl ConversationItemStore for SqliteResponseStore {
    async fn create_conversation_items(&self, items: &[ConversationItemRecord]) -> Result<(), StoreError> {
        let table = self
            .tables
            .items
            .as_deref()
            .ok_or_else(|| StoreError::Unavailable("items table not configured".to_owned()))?;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let sql = format!(
            "INSERT INTO {table} \
             (item_id, tenant_id, conversation_id, item_data, created_at, position) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(item_id, tenant_id) DO UPDATE SET \
             conversation_id = excluded.conversation_id, \
             item_data = excluded.item_data, \
             created_at = excluded.created_at, \
             position = excluded.position"
        );

        for item in items {
            let item_data =
                serde_json::to_string(&item.item_data).map_err(|e| StoreError::Serialization(e.to_string()))?;

            sqlx::query(AssertSqlSafe(sql.as_str()))
                .bind(&item.item_id)
                .bind(&item.tenant_id)
                .bind(&item.conversation_id)
                .bind(&item_data)
                .bind(item.created_at)
                .bind(item.position)
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        tx.commit().await.map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn list_conversation_items(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        after_item_id: Option<&str>,
        limit: u32,
        ascending: bool,
    ) -> Result<Vec<ConversationItemRecord>, StoreError> {
        let table = self
            .tables
            .items
            .as_deref()
            .ok_or_else(|| StoreError::Unavailable("items table not configured".to_owned()))?;

        let direction = if ascending { "ASC" } else { "DESC" };
        let cursor_operator = if ascending { ">" } else { "<" };

        let rows = if let Some(item_id) = after_item_id {
            let Some(position) = self
                .conversation_item_position(tenant_id, conversation_id, item_id)
                .await?
            else {
                return Ok(Vec::new());
            };
            let sql = format!(
                "SELECT item_id, tenant_id, conversation_id, item_data, created_at, position \
                 FROM {table} \
                 WHERE tenant_id = ? AND conversation_id = ? \
                   AND (position {cursor_operator} ? \
                        OR (position = ? AND item_id {cursor_operator} ?)) \
                 ORDER BY position {direction}, item_id {direction} \
                 LIMIT ?"
            );
            sqlx::query(AssertSqlSafe(sql.as_str()))
                .bind(tenant_id)
                .bind(conversation_id)
                .bind(position)
                .bind(position)
                .bind(item_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?
        } else {
            let sql = format!(
                "SELECT item_id, tenant_id, conversation_id, item_data, created_at, position \
                 FROM {table} \
                 WHERE tenant_id = ? AND conversation_id = ? \
                 ORDER BY position {direction}, item_id {direction} \
                 LIMIT ?"
            );
            sqlx::query(AssertSqlSafe(sql.as_str()))
                .bind(tenant_id)
                .bind(conversation_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?
        };

        rows.iter().map(row_to_conversation_item_record).collect()
    }

    async fn get_conversation_item(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        item_id: &str,
    ) -> Result<Option<ConversationItemRecord>, StoreError> {
        let table = self
            .tables
            .items
            .as_deref()
            .ok_or_else(|| StoreError::Unavailable("items table not configured".to_owned()))?;

        let sql = format!(
            "SELECT item_id, tenant_id, conversation_id, item_data, created_at, position \
             FROM {table} \
             WHERE item_id = ? AND tenant_id = ? AND conversation_id = ?"
        );

        let row = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(item_id)
            .bind(tenant_id)
            .bind(conversation_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| row_to_conversation_item_record(&r)).transpose()
    }

    async fn delete_conversation_item(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        item_id: &str,
    ) -> Result<bool, StoreError> {
        let table = self
            .tables
            .items
            .as_deref()
            .ok_or_else(|| StoreError::Unavailable("items table not configured".to_owned()))?;

        let sql = format!("DELETE FROM {table} WHERE item_id = ? AND tenant_id = ? AND conversation_id = ?");

        let result = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(item_id)
            .bind(tenant_id)
            .bind(conversation_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    async fn conversation_item_position(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        item_id: &str,
    ) -> Result<Option<i64>, StoreError> {
        let table = self
            .tables
            .items
            .as_deref()
            .ok_or_else(|| StoreError::Unavailable("items table not configured".to_owned()))?;

        let sql = format!(
            "SELECT position FROM {table} \
             WHERE item_id = ? AND tenant_id = ? AND conversation_id = ?"
        );

        let row = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(item_id)
            .bind(tenant_id)
            .bind(conversation_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| r.try_get("position").map_err(|e| StoreError::Database(e.to_string())))
            .transpose()
    }

    async fn max_item_position(&self, tenant_id: &str, conversation_id: &str) -> Result<i64, StoreError> {
        let table = self
            .tables
            .items
            .as_deref()
            .ok_or_else(|| StoreError::Unavailable("items table not configured".to_owned()))?;

        let sql = format!(
            "SELECT COALESCE(MAX(position), 0) AS max_pos \
             FROM {table} \
             WHERE tenant_id = ? AND conversation_id = ?"
        );

        let row = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(tenant_id)
            .bind(conversation_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.try_get("max_pos").map_err(|e| StoreError::Database(e.to_string()))
    }

    async fn delete_conversation_items(&self, tenant_id: &str, conversation_id: &str) -> Result<(), StoreError> {
        let table = self
            .tables
            .items
            .as_deref()
            .ok_or_else(|| StoreError::Unavailable("items table not configured".to_owned()))?;

        let sql = format!("DELETE FROM {table} WHERE tenant_id = ? AND conversation_id = ?");

        sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(tenant_id)
            .bind(conversation_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Row Conversion
// -----------------------------------------------------------------------------

/// Convert a sqlx row to a [`ResponseRecord`].
fn row_to_response_record(row: &sqlx::sqlite::SqliteRow) -> Result<ResponseRecord, StoreError> {
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

/// Convert a sqlx row to a [`ConversationItemRecord`].
fn row_to_conversation_item_record(row: &sqlx::sqlite::SqliteRow) -> Result<ConversationItemRecord, StoreError> {
    let item_data_json: String = row
        .try_get("item_data")
        .map_err(|e| StoreError::Database(e.to_string()))?;

    Ok(ConversationItemRecord {
        item_id: row
            .try_get("item_id")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        conversation_id: row
            .try_get("conversation_id")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        item_data: serde_json::from_str(&item_data_json).map_err(|e| StoreError::Serialization(e.to_string()))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| StoreError::Database(e.to_string()))?,
        position: row
            .try_get("position")
            .map_err(|e| StoreError::Database(e.to_string()))?,
    })
}

/// Convert a sqlx row to a [`ConversationRecord`].
fn row_to_conversation_record(row: &sqlx::sqlite::SqliteRow) -> Result<ConversationRecord, StoreError> {
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
