//! Playground endpoints — Datastar SSE-driven browser REPL.
//!
//! Three SSE endpoints that use the Datastar SDK to drive the frontend:
//! - `POST /playground/init` — Initialize a compliance vertical with schema + sample data
//! - `POST /playground/query` — Execute a read-only SQL query
//! - `POST /playground/schema` — Refresh the schema tree

use axum::{
    extract::State,
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
};
use datastar::{
    axum::ReadSignals,
    prelude::{ElementPatchMode, ExecuteScript, PatchElements, PatchSignals},
};
use html_escape::encode_text;
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::state::StudioState;
use crate::templates;

// Embedded schema SQL for the healthcare playground.
const HEALTHCARE_SQL: &str = include_str!("../../../../examples/healthcare/schema.sql");

// Playground tenant ID (isolated from user data).
const HEALTHCARE_TENANT: u64 = 100;

// Rate limiting
const MAX_QUERIES_PER_MINUTE: u32 = 30;
const RATE_WINDOW_SECS: u64 = 60;

// Result limits
const MAX_ROWS: usize = 1000;
const QUERY_TIMEOUT_SECS: u64 = 5;

/// Signals received from `POST /playground/init`.
#[derive(Debug, Deserialize)]
pub struct InitSignals {
    pub vertical: String,
}

/// Signals received from `POST /playground/query`.
#[derive(Debug, Deserialize)]
pub struct QuerySignals {
    pub vertical: String,
    pub query: String,
}

/// Signals received from `POST /playground/schema`.
#[derive(Debug, Deserialize)]
pub struct SchemaSignals {
    pub vertical: String,
}

/// Resolves a vertical name to its tenant ID. Only `healthcare` is supported;
/// the parameter is retained for wire-compatibility with the existing UI.
fn tenant_for_vertical(vertical: &str) -> Option<u64> {
    match vertical {
        "healthcare" => Some(HEALTHCARE_TENANT),
        _ => None,
    }
}

/// Returns the schema SQL for a vertical. Only `healthcare` is supported.
fn sql_for_vertical(vertical: &str) -> Option<&'static str> {
    match vertical {
        "healthcare" => Some(HEALTHCARE_SQL),
        _ => None,
    }
}

/// Checks whether a query is read-only (SELECT, WITH, EXPLAIN, or meta-command).
fn is_read_only(query: &str) -> bool {
    let trimmed = query.trim().to_uppercase();
    trimmed.starts_with("SELECT")
        || trimmed.starts_with("WITH")
        || trimmed.starts_with("EXPLAIN")
        || trimmed.starts_with('.')
}

/// Per-IP rate limiter state.
#[derive(Debug, Clone, Default)]
pub struct RateLimiter {
    entries: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
}

impl RateLimiter {
    /// Checks and increments the rate limit for an IP. Returns `true` if allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.entries.lock().expect("rate limiter lock poisoned");
        let now = Instant::now();
        let entry = map.entry(ip).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) > Duration::from_secs(RATE_WINDOW_SECS) {
            *entry = (0, now);
        }

        if entry.0 >= MAX_QUERIES_PER_MINUTE {
            return false;
        }

        entry.0 += 1;
        true
    }
}

/// Initialize a compliance vertical with schema and sample data.
///
/// POST /playground/init
pub async fn init_vertical(
    State(state): State<StudioState>,
    ReadSignals(signals): ReadSignals<InitSignals>,
) -> impl IntoResponse {
    let vertical = signals.vertical.clone();
    let db_address = state.db_address.clone();

    let stream = async_stream::stream! {
        // Signal loading
        let patch = PatchSignals::new(r#"{"loading": true, "initialized": false, "error": null}"#);
        yield Ok::<Event, Infallible>(patch.write_as_axum_sse_event());

        // Validate vertical
        let (tenant_id, schema_sql) = match (tenant_for_vertical(&vertical), sql_for_vertical(&vertical)) {
            (Some(t), Some(s)) => (t, s),
            _ => {
                let html = templates::render_error("Invalid Vertical", &format!("Unknown vertical: {vertical}"));
                let patch = PatchElements::new(html)
                    .selector("#playground-results")
                    .mode(ElementPatchMode::Inner);
                yield Ok(patch.write_as_axum_sse_event());

                let patch = PatchSignals::new(r#"{"loading": false}"#);
                yield Ok(patch.write_as_axum_sse_event());
                return;
            }
        };

        // Check if already initialized
        let already_init = {
            let set = state.initialized_verticals.lock().expect("lock poisoned");
            set.contains(&vertical)
        };

        if !already_init {
            // Execute schema SQL statements
            let schema_owned = schema_sql.to_string();
            let db = db_address.clone();
            let result = tokio::task::spawn_blocking(move || {
                use kimberlite_client::{Client, ClientConfig};
                use kimberlite_types::TenantId;

                let config = ClientConfig::default();
                let mut client = Client::connect(&db, TenantId::new(tenant_id), config)?;

                // Split on semicolons and execute each statement
                for stmt in schema_owned.split(';') {
                    let trimmed = stmt.trim();
                    if trimmed.is_empty() || trimmed.starts_with("--") {
                        continue;
                    }
                    // Ignore errors from duplicate tables (idempotent init)
                    let _ = client.query(trimmed, &[]);
                }
                Ok::<(), anyhow::Error>(())
            }).await;

            match result {
                Ok(Ok(())) => {
                    let mut set = state.initialized_verticals.lock().expect("lock poisoned");
                    set.insert(vertical.clone());
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, vertical = %vertical, "Failed to initialize vertical");
                    // Continue anyway — tables may already exist
                }
                Err(e) => {
                    tracing::error!(error = %e, "Init task panicked");
                    let html = templates::render_error("Initialization Error", "Failed to set up schema");
                    let patch = PatchElements::new(html)
                        .selector("#playground-results")
                        .mode(ElementPatchMode::Inner);
                    yield Ok(patch.write_as_axum_sse_event());

                    let patch = PatchSignals::new(r#"{"loading": false}"#);
                    yield Ok(patch.write_as_axum_sse_event());
                    return;
                }
            }
        }

        // Discover schema for the vertical
        let schema_tables = discover_tables(&db_address, tenant_id).await;
        let table_names: Vec<String> = schema_tables.iter().map(|(name, _)| name.clone()).collect();

        // Render schema tree
        let vertical_label = match vertical.as_str() {
            "healthcare" => "Healthcare (HIPAA)",
            _ => &vertical,
        };
        let schema_html = templates::render_schema_tree(tenant_id, vertical_label, &schema_tables);
        let patch = PatchElements::new(schema_html)
            .selector("#playground-schema")
            .mode(ElementPatchMode::Inner);
        yield Ok(patch.write_as_axum_sse_event());

        // Render example queries
        let examples_html = render_example_queries(&vertical);
        let patch = PatchElements::new(examples_html)
            .selector("#playground-examples")
            .mode(ElementPatchMode::Inner);
        yield Ok(patch.write_as_axum_sse_event());

        // Inject table names for client-side completion
        let table_names_js = table_names
            .iter()
            .map(|n| format!("\"{}\"", encode_text(n)))
            .collect::<Vec<_>>()
            .join(", ");
        let script = format!("window.PLAYGROUND_TABLES = [{table_names_js}];");
        let exec = ExecuteScript::new(script);
        yield Ok(exec.write_as_axum_sse_event());

        // Signal ready
        let patch = PatchSignals::new(r#"{"loading": false, "initialized": true}"#);
        yield Ok(patch.write_as_axum_sse_event());
    };

    Sse::new(stream)
}

/// Execute a read-only SQL query.
///
/// POST /playground/query
pub async fn execute_query(
    State(state): State<StudioState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    ReadSignals(signals): ReadSignals<QuerySignals>,
) -> impl IntoResponse {
    let vertical = signals.vertical.clone();
    let query = signals.query.clone();
    let db_address = state.db_address.clone();
    let rate_limiter = state.rate_limiter.clone();
    let client_ip = addr.ip();

    let stream = async_stream::stream! {
        // Signal loading
        let patch = PatchSignals::new(r#"{"loading": true, "error": null}"#);
        yield Ok::<Event, Infallible>(patch.write_as_axum_sse_event());

        // Rate limit check
        if !rate_limiter.check(client_ip) {
            let html = templates::render_error(
                "Rate Limited",
                "Too many queries. Please wait a moment before trying again.",
            );
            let patch = PatchElements::new(html)
                .selector("#playground-results")
                .mode(ElementPatchMode::Inner);
            yield Ok(patch.write_as_axum_sse_event());

            let patch = PatchSignals::new(r#"{"loading": false}"#);
            yield Ok(patch.write_as_axum_sse_event());
            return;
        }

        // Validate vertical
        let tenant_id = match tenant_for_vertical(&vertical) {
            Some(t) => t,
            None => {
                let html = templates::render_error("Error", "Select a vertical first");
                let patch = PatchElements::new(html)
                    .selector("#playground-results")
                    .mode(ElementPatchMode::Inner);
                yield Ok(patch.write_as_axum_sse_event());

                let patch = PatchSignals::new(r#"{"loading": false}"#);
                yield Ok(patch.write_as_axum_sse_event());
                return;
            }
        };

        // Read-only enforcement
        if !is_read_only(&query) {
            let html = templates::render_error(
                "Read-Only Mode",
                "The playground only allows SELECT, WITH, and EXPLAIN queries.",
            );
            let patch = PatchElements::new(html)
                .selector("#playground-results")
                .mode(ElementPatchMode::Inner);
            yield Ok(patch.write_as_axum_sse_event());

            let patch = PatchSignals::new(r#"{"loading": false}"#);
            yield Ok(patch.write_as_axum_sse_event());
            return;
        }

        // Execute query with timeout
        let query_owned = query.clone();
        let start = std::time::Instant::now();

        let result = tokio::time::timeout(
            Duration::from_secs(QUERY_TIMEOUT_SECS),
            tokio::task::spawn_blocking(move || {
                use kimberlite_client::{Client, ClientConfig};
                use kimberlite_types::TenantId;

                let config = ClientConfig::default();
                let mut client = Client::connect(&db_address, TenantId::new(tenant_id), config)?;
                client.query(&query_owned, &[])
            }),
        ).await;

        let elapsed_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(Ok(query_response))) => {
                let columns: Vec<String> = query_response.columns.iter().map(|c| c.to_string()).collect();
                let mut rows: Vec<Vec<String>> = query_response
                    .rows
                    .iter()
                    .map(|row| row.iter().map(format_query_value).collect())
                    .collect();

                let total_rows = rows.len();
                let truncated = total_rows > MAX_ROWS;
                if truncated {
                    rows.truncate(MAX_ROWS);
                }

                let mut html = templates::render_query_results(&columns, &rows);

                if truncated {
                    html.push_str(&format!(
                        "<div class=\"results-table__meta\" style=\"color: var(--text-warning);\">Results truncated: showing {MAX_ROWS} of {total_rows} rows</div>",
                    ));
                }

                let patch = PatchElements::new(html)
                    .selector("#playground-results")
                    .mode(ElementPatchMode::Inner);
                yield Ok(patch.write_as_axum_sse_event());

                let row_count = if truncated { MAX_ROWS } else { total_rows };
                let patch = PatchSignals::new(format!(
                    r#"{{"loading": false, "execution_time_ms": {elapsed_ms}, "row_count": {row_count}}}"#,
                ));
                yield Ok(patch.write_as_axum_sse_event());

                tracing::info!(
                    vertical = %vertical,
                    query = %query,
                    row_count = total_rows,
                    elapsed_ms,
                    "Playground query executed"
                );
            }
            Ok(Ok(Err(e))) => {
                let html = templates::render_error("Query Error", &e.to_string());
                let patch = PatchElements::new(html)
                    .selector("#playground-results")
                    .mode(ElementPatchMode::Inner);
                yield Ok(patch.write_as_axum_sse_event());

                let patch = PatchSignals::new(r#"{"loading": false, "row_count": 0}"#);
                yield Ok(patch.write_as_axum_sse_event());
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "Query task panicked");
                let html = templates::render_error("Internal Error", "Query execution failed unexpectedly");
                let patch = PatchElements::new(html)
                    .selector("#playground-results")
                    .mode(ElementPatchMode::Inner);
                yield Ok(patch.write_as_axum_sse_event());

                let patch = PatchSignals::new(r#"{"loading": false, "row_count": 0}"#);
                yield Ok(patch.write_as_axum_sse_event());
            }
            Err(_) => {
                let html = templates::render_error("Timeout", "Query exceeded the 5-second time limit");
                let patch = PatchElements::new(html)
                    .selector("#playground-results")
                    .mode(ElementPatchMode::Inner);
                yield Ok(patch.write_as_axum_sse_event());

                let patch = PatchSignals::new(r#"{"loading": false, "row_count": 0}"#);
                yield Ok(patch.write_as_axum_sse_event());
            }
        }
    };

    Sse::new(stream)
}

/// Refresh the schema tree for a vertical.
///
/// POST /playground/schema
pub async fn refresh_schema(
    State(state): State<StudioState>,
    ReadSignals(signals): ReadSignals<SchemaSignals>,
) -> impl IntoResponse {
    let vertical = signals.vertical.clone();
    let db_address = state.db_address.clone();

    let stream = async_stream::stream! {
        let tenant_id = match tenant_for_vertical(&vertical) {
            Some(t) => t,
            None => return,
        };

        let vertical_label = match vertical.as_str() {
            "healthcare" => "Healthcare (HIPAA)",
            _ => &vertical,
        };

        let schema_tables = discover_tables(&db_address, tenant_id).await;

        let schema_html = templates::render_schema_tree(tenant_id, vertical_label, &schema_tables);
        let patch = PatchElements::new(schema_html)
            .selector("#playground-schema")
            .mode(ElementPatchMode::Inner);
        yield Ok::<Event, Infallible>(patch.write_as_axum_sse_event());
    };

    Sse::new(stream)
}

/// Discover tables and columns for a tenant.
async fn discover_tables(db_address: &str, tenant_id: u64) -> Vec<(String, Vec<String>)> {
    let db = db_address.to_string();

    tokio::task::spawn_blocking(move || {
        use kimberlite_client::{Client, ClientConfig};
        use kimberlite_types::TenantId;

        let config = ClientConfig::default();
        let mut client = match Client::connect(&db, TenantId::new(tenant_id), config) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        // Discover tables via SHOW TABLES
        let table_names: Vec<String> = match client.query("SHOW TABLES", &[]) {
            Ok(resp) => resp
                .rows
                .iter()
                .filter_map(|row| row.first().map(format_query_value))
                .collect(),
            Err(_) => return vec![],
        };

        // Get columns for each table via SHOW COLUMNS FROM <table>
        table_names
            .into_iter()
            .map(|name| {
                let columns = match client.query(&format!("SHOW COLUMNS FROM {name}"), &[]) {
                    Ok(resp) => resp
                        .rows
                        .iter()
                        .filter_map(|row| {
                            let col_name = row.first().map(format_query_value)?;
                            let col_type = row.get(1).map(format_query_value).unwrap_or_default();
                            Some(format!("{col_name} ({col_type})"))
                        })
                        .collect(),
                    Err(_) => vec![],
                };
                (name, columns)
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// Renders example query buttons for a vertical.
fn render_example_queries(vertical: &str) -> String {
    let examples: Vec<(&str, &str)> = match vertical {
        "healthcare" => vec![
            (
                "List patients",
                "SELECT id, first_name, last_name, date_of_birth FROM patients;",
            ),
            (
                "Encounters by patient",
                "SELECT p.first_name, p.last_name, e.encounter_type, e.encounter_date, e.chief_complaint FROM encounters e JOIN patients p ON e.patient_id = p.id;",
            ),
            (
                "Provider workload",
                "SELECT pr.first_name, pr.last_name, pr.specialty, COUNT(e.id) AS encounter_count FROM providers pr LEFT JOIN encounters e ON pr.id = e.provider_id GROUP BY pr.id, pr.first_name, pr.last_name, pr.specialty;",
            ),
            (
                "Audit trail",
                "SELECT timestamp, user_id, action, resource_type, resource_id FROM audit_log ORDER BY timestamp;",
            ),
            (
                "PHI access report",
                "SELECT a.timestamp, a.user_id, a.action, p.first_name, p.last_name FROM audit_log a JOIN patients p ON a.resource_id = p.id WHERE a.resource_type = 'patient';",
            ),
        ],
        _ => vec![],
    };

    let mut html = String::from("<div class=\"flow\" data-space=\"xs\">");
    html.push_str("<h3 style=\"font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; margin: 0; color: var(--text-secondary);\">Example Queries</h3>");

    for (label, query) in &examples {
        // Escape both the label and query for safe HTML embedding
        let escaped_query = encode_text(query).replace('\'', "\\'");
        html.push_str(&format!(
            "<button type=\"button\" class=\"button playground-example\" data-variant=\"ghost\" \
             data-on-click=\"$query = '{}'; @post('/playground/query')\">\
             {}</button>",
            escaped_query,
            encode_text(label),
        ));
    }

    html.push_str("</div>");
    html
}

/// Formats a wire QueryValue to a display string (same as routes/api.rs).
fn format_query_value(val: &kimberlite_client::QueryValue) -> String {
    match val {
        kimberlite_client::QueryValue::Null => "NULL".to_string(),
        kimberlite_client::QueryValue::BigInt(i) => i.to_string(),
        kimberlite_client::QueryValue::Text(s) => s.clone(),
        kimberlite_client::QueryValue::Boolean(b) => b.to_string(),
        kimberlite_client::QueryValue::Timestamp(ts) => ts.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_read_only() {
        assert!(is_read_only("SELECT * FROM patients"));
        assert!(is_read_only("  select * from patients"));
        assert!(is_read_only("WITH cte AS (SELECT 1) SELECT * FROM cte"));
        assert!(is_read_only("EXPLAIN SELECT * FROM patients"));
        assert!(is_read_only(".tables"));

        assert!(!is_read_only("INSERT INTO patients VALUES (1)"));
        assert!(!is_read_only("UPDATE patients SET name = 'x'"));
        assert!(!is_read_only("DELETE FROM patients"));
        assert!(!is_read_only("DROP TABLE patients"));
        assert!(!is_read_only("CREATE TABLE foo (id BIGINT)"));
        assert!(!is_read_only("ALTER TABLE patients ADD COLUMN x TEXT"));
    }

    #[test]
    fn test_tenant_for_vertical() {
        assert_eq!(tenant_for_vertical("healthcare"), Some(100));
        assert_eq!(tenant_for_vertical("finance"), None);
        assert_eq!(tenant_for_vertical("legal"), None);
        assert_eq!(tenant_for_vertical("unknown"), None);
    }

    #[test]
    fn test_sql_for_vertical() {
        assert!(sql_for_vertical("healthcare").is_some());
        assert!(sql_for_vertical("finance").is_none());
        assert!(sql_for_vertical("legal").is_none());
        assert!(sql_for_vertical("unknown").is_none());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Should allow up to MAX_QUERIES_PER_MINUTE
        for _ in 0..MAX_QUERIES_PER_MINUTE {
            assert!(limiter.check(ip));
        }

        // Should reject after limit
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_render_example_queries() {
        let html = render_example_queries("healthcare");
        assert!(html.contains("List patients"));
        assert!(html.contains("Encounters by patient"));
        assert!(html.contains("@post"));

        let html = render_example_queries("unknown");
        assert!(html.contains("Example Queries"));
    }

    #[test]
    fn test_example_queries_xss_safe() {
        // The render function should escape HTML in labels/queries
        let html = render_example_queries("healthcare");
        // No raw angle brackets from query content should appear unescaped
        assert!(!html.contains("<script>"));
    }
}
