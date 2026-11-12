/*
 * Author: Windmill Labs, Inc
 * Copyright: Windmill Labs, Inc 2024
 * This file and its contents are licensed under the AGPLv3 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-AGPL for a copy of the license.
 */

use std::future::Future;
use std::sync::Arc;

use windmill_common::db::DB;
use windmill_common::error::{self, Error};
use windmill_oauth::{OAuthAccountInfo, RefreshError, RefreshedToken};

/// The `account` row a refresh starts from.
pub struct RefreshAccount {
    pub mcp_server_url: Option<String>,
    pub is_workspace_integration: bool,
    pub info: OAuthAccountInfo,
}

lazy_static::lazy_static! {
    static ref REFRESH_LOCKS: dashmap::DashMap<(String, i32), Arc<tokio::sync::Mutex<()>>> =
        dashmap::DashMap::new();
}

/// Refresh the token of account `id`, which backs the secret variable at `path`.
///
/// No connection is held across `exchange`: it does its own config reads and the provider
/// call, and every write here is a single autocommit statement. Concurrent refreshers of one
/// account are serialized within a process, and across processes the account is only
/// committed if its refresh token is still the one exchanged, so a rotated refresh token is
/// never overwritten by a stale one. An account refreshed by someone else while we waited for
/// the lock is not refreshed again: without `force` any fresh account counts, with it only one
/// whose expiry moved since we asked. Callers must have authorized `w_id`/`path`/`id`.
pub(crate) async fn refresh_account_token<F, Fut>(
    db: &DB,
    w_id: &str,
    path: &str,
    id: i32,
    force: bool,
    exchange: F,
) -> error::Result<String>
where
    F: FnOnce(RefreshAccount) -> Fut,
    Fut: Future<Output = Result<RefreshedToken, RefreshError>>,
{
    let seen_expiry = if force {
        sqlx::query_scalar!(
            "SELECT expires_at FROM account WHERE workspace_id = $1 AND id = $2",
            w_id,
            id
        )
        .fetch_optional(db)
        .await?
    } else {
        None
    };

    let lock = REFRESH_LOCKS
        .entry((w_id.to_string(), id))
        .or_default()
        .clone();
    let _guard = lock.lock().await;

    let row = sqlx::query!(
        "SELECT mcp_server_url, is_workspace_integration, client, refresh_token, grant_type,
            cc_client_id, cc_client_secret, cc_token_url, scopes, expires_at,
            now() > expires_at AS \"expired!\"
         FROM account WHERE workspace_id = $1 AND id = $2",
        w_id,
        id,
    )
    .fetch_optional(db)
    .await?
    .ok_or_else(|| Error::NotFound(format!("Account {id} not found")))?;

    // A failed store moves `expires_at` too, into the past: only a fresh account counts.
    let refreshed_meanwhile = !row.expired && (!force || Some(row.expires_at) != seen_expiry);
    if refreshed_meanwhile {
        return current_token(db, w_id, path).await;
    }

    let used = row.refresh_token.clone();
    let account = RefreshAccount {
        mcp_server_url: row.mcp_server_url,
        is_workspace_integration: row.is_workspace_integration,
        info: OAuthAccountInfo {
            client: row.client,
            refresh_token: row.refresh_token,
            grant_type: row.grant_type,
            cc_client_id: row.cc_client_id,
            cc_client_secret: row.cc_client_secret,
            cc_token_url: row.cc_token_url,
            scopes: row.scopes,
        },
    };

    let token = match exchange(account).await {
        Ok(token) => token,
        Err(RefreshError::Other(e)) => return Err(e),
        Err(RefreshError::Provider(msg)) => {
            let recorded = sqlx::query!(
                "UPDATE account SET refresh_error = $1
                 WHERE workspace_id = $2 AND id = $3 AND refresh_token = $4",
                msg,
                w_id,
                id,
                used,
            )
            .execute(db)
            .await?
            .rows_affected();
            // Another process rotated the refresh token first, so the one we sent was spent:
            // its token is the one to serve, unless storing it failed too.
            if recorded == 0 {
                let expired = sqlx::query_scalar!(
                    "SELECT now() > expires_at AS \"expired!\" FROM account
                     WHERE workspace_id = $1 AND id = $2",
                    w_id,
                    id
                )
                .fetch_optional(db)
                .await?;
                if expired == Some(false) {
                    return current_token(db, w_id, path).await;
                }
            }
            return Err(Error::BadRequest(format!("Error refreshing token: {msg}")));
        }
    };

    // The lifetime runs from the exchange, not from the end of the stores below.
    let expires_at = windmill_common::utils::now_from_db(db).await?
        + chrono::Duration::try_seconds(token.expires_in).unwrap_or_default();

    // Store at every secret variable of the account before marking it fresh, so no reader of
    // any of them sees the account fresh with the old token. A failed store already marks the
    // account for a retry; the rotated refresh token must still be saved, or the next refresh
    // sends one the provider has revoked.
    let mut paths = sqlx::query_scalar!(
        "SELECT path FROM variable WHERE workspace_id = $1 AND account = $2 AND is_secret",
        w_id,
        id
    )
    .fetch_all(db)
    .await?;
    if !paths.iter().any(|p| p == path) {
        paths.push(path.to_string());
    }
    let mut stored = Ok(());
    for p in &paths {
        stored =
            crate::secret_backend_ext::store_oauth_token_value(db, w_id, p, &token.access_token)
                .await;
        if stored.is_err() {
            break;
        }
    }
    sqlx::query!(
        "UPDATE account SET refresh_token = COALESCE($1, refresh_token),
            expires_at = CASE WHEN $2 THEN $3 ELSE expires_at END,
            refresh_error = CASE WHEN $2 THEN NULL ELSE refresh_error END
         WHERE workspace_id = $4 AND id = $5 AND refresh_token = $6",
        token.refresh_token,
        stored.is_ok(),
        expires_at,
        w_id,
        id,
        used,
    )
    .execute(db)
    .await?;
    stored?;

    Ok(token.access_token)
}

async fn current_token(db: &DB, w_id: &str, path: &str) -> error::Result<String> {
    let value = sqlx::query_scalar!(
        "SELECT value::text AS \"value!\" FROM variable WHERE workspace_id = $1 AND path = $2",
        w_id,
        path
    )
    .fetch_optional(db)
    .await?
    .ok_or_else(|| Error::NotFound(format!("Variable {path} not found")))?;
    crate::secret_backend_ext::get_secret_value(db, w_id, path, &value).await
}

/// The standard OAuth / client-credentials exchange.
pub(crate) async fn exchange_standard(
    db: &DB,
    w_id: &str,
    id: i32,
    account: &OAuthAccountInfo,
) -> Result<RefreshedToken, RefreshError> {
    windmill_oauth::exchange_account_token(
        db,
        w_id,
        id,
        account,
        &*windmill_oauth::OAUTH_CLIENTS.load(),
        &windmill_oauth::OAUTH_HTTP_CLIENT,
        include_str!("../../oauth_connect.json"),
    )
    .await
}

pub async fn _refresh_token(
    path: &str,
    w_id: &str,
    id: i32,
    db: &DB,
    force: bool,
) -> error::Result<String> {
    #[cfg(feature = "mcp")]
    {
        let is_mcp: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account WHERE workspace_id = $1 AND id = $2 AND client = 'mcp')",
        ).bind(w_id).bind(id).fetch_one(db).await?;
        if is_mcp {
            return refresh_mcp_account(path, w_id, id, db, force, false)
                .await?
                .ok_or_else(|| Error::InternalErr("MCP refresh unexpectedly skipped".into()));
        }
    }
    #[cfg(feature = "private")]
    return crate::oauth_refresh_ee::_refresh_token(path, w_id, id, db, force).await;
    #[cfg(not(feature = "private"))]
    refresh_account_token(db, w_id, path, id, force, |account| async move {
        exchange_standard(db, w_id, id, &account.info).await
    })
    .await
}

#[cfg(feature = "mcp")]
pub async fn refresh_mcp_account_background(
    path: &str,
    w_id: &str,
    id: i32,
    db: &DB,
) -> error::Result<()> {
    refresh_mcp_account(path, w_id, id, db, false, true)
        .await
        .map(|_| ())
}

#[cfg(feature = "mcp")]
async fn refresh_mcp_account(
    path: &str,
    w_id: &str,
    id: i32,
    db: &DB,
    force: bool,
    background: bool,
) -> error::Result<Option<String>> {
    // Rotating tokens are single-use. Hold this lock through the exchange, secret writes,
    // and retry-state update so replicas cannot retry a failure before its cooldown is saved.
    let mut lock = db.begin().await?;
    if background {
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(1464683843, $1)")
            .bind(id)
            .fetch_one(&mut *lock)
            .await?;
        if !acquired {
            return Ok(None);
        }
        let due: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM account a
                LEFT JOIN mcp_oauth_refresh_state s
                  ON s.workspace_id = a.workspace_id AND s.account_id = a.id
                WHERE a.workspace_id = $1 AND a.id = $2 AND a.client = 'mcp'
                  AND a.expires_at <= now() AND a.refresh_token <> ''
                  AND (s.next_attempt_at IS NULL OR s.next_attempt_at <= now())
            )",
        )
        .bind(w_id)
        .bind(id)
        .fetch_one(&mut *lock)
        .await?;
        if !due {
            return Ok(None);
        }
    } else {
        sqlx::query("SELECT pg_advisory_xact_lock(1464683843, $1)")
            .bind(id)
            .execute(&mut *lock)
            .await?;
    }

    let result = refresh_account_token(db, w_id, path, id, force, |account| async move {
        let server = account
            .mcp_server_url
            .as_deref()
            .ok_or_else(|| Error::BadRequest("MCP account has no server URL".into()))?;
        let token = windmill_mcp::client_registration::refresh_mcp_token(
            db,
            server,
            &account.info.refresh_token,
            account.info.scopes.as_deref(),
        )
        .await
        .map_err(|_| {
            RefreshError::Provider("MCP OAuth refresh failed; reconnect the server".into())
        })?;
        Ok(RefreshedToken {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_in: token
                .expires_in
                .and_then(|v| i64::try_from(v).ok())
                .unwrap_or(3600),
        })
    })
    .await;

    if result.is_ok() {
        sqlx::query(
            "DELETE FROM mcp_oauth_refresh_state WHERE workspace_id = $1 AND account_id = $2",
        )
        .bind(w_id)
        .bind(id)
        .execute(&mut *lock)
        .await?;
    } else {
        // SELECT avoids recreating retry state if the account was deleted during the exchange.
        sqlx::query(
            "INSERT INTO mcp_oauth_refresh_state AS s
                (workspace_id, account_id, failure_count, next_attempt_at)
             SELECT workspace_id, id, 1, clock_timestamp() + interval '1 minute'
             FROM account WHERE workspace_id = $1 AND id = $2
             ON CONFLICT (workspace_id, account_id) DO UPDATE
             SET failure_count = LEAST(s.failure_count + 1, 32),
                 next_attempt_at = clock_timestamp() +
                     LEAST(3600, 60 * power(2, LEAST(s.failure_count, 6))) * interval '1 second'",
        )
        .bind(w_id)
        .bind(id)
        .execute(&mut *lock)
        .await?;
    }
    lock.commit().await?;
    result.map(Some)
}

#[cfg(all(test, feature = "mcp"))]
mod mcp_retry_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a migrated development database"]
    async fn cooldown_serializes_replicas_but_allows_on_demand_recovery() -> anyhow::Result<()> {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&std::env::var("DATABASE_URL")?)
            .await?;
        let workspace = format!("mcp-retry-{}", uuid::Uuid::new_v4().simple());
        sqlx::query("INSERT INTO workspace (id, name, owner) VALUES ($1, $1, 'test')")
            .bind(&workspace)
            .execute(&db)
            .await?;
        let result: anyhow::Result<()> = async {
            sqlx::query("INSERT INTO workspace_key (workspace_id, kind, key) VALUES ($1, 'cloud', 'retry-test')")
                .bind(&workspace).execute(&db).await?;
            let id: i32 = sqlx::query_scalar(
                "INSERT INTO account (workspace_id, client, refresh_token, expires_at)
                 VALUES ($1, 'mcp', 'unused', now() - interval '1 hour') RETURNING id",
            ).bind(&workspace).fetch_one(&db).await?;
            let path = "u/test/mcp_retry";
            let stored = crate::secret_backend_ext::store_secret_value(&db, &workspace, path, "recovered").await?;
            sqlx::query("INSERT INTO variable (workspace_id, path, value, is_secret, account) VALUES ($1, $2, $3, true, $4)")
                .bind(&workspace).bind(path).bind(stored).bind(id).execute(&db).await?;

            // No server URL: deterministic failure without contacting a provider.
            assert!(refresh_mcp_account_background(path, &workspace, id, &db).await.is_err());
            let first: (i32, f64) = sqlx::query_as(
                "SELECT failure_count, extract(epoch FROM next_attempt_at - clock_timestamp())::float8
                 FROM mcp_oauth_refresh_state WHERE workspace_id = $1 AND account_id = $2",
            ).bind(&workspace).bind(id).fetch_one(&db).await?;
            assert_eq!(first.0, 1);
            assert!((50.0..=60.0).contains(&first.1));
            refresh_mcp_account_background(path, &workspace, id, &db).await?;
            let count: i32 = sqlx::query_scalar("SELECT failure_count FROM mcp_oauth_refresh_state WHERE workspace_id = $1 AND account_id = $2")
                .bind(&workspace).bind(id).fetch_one(&db).await?;
            assert_eq!(count, 1, "another sweep must respect the persisted cooldown");

            assert!(_refresh_token(path, &workspace, id, &db, false).await.is_err());
            let second: (i32, f64) = sqlx::query_as(
                "SELECT failure_count, extract(epoch FROM next_attempt_at - clock_timestamp())::float8
                 FROM mcp_oauth_refresh_state WHERE workspace_id = $1 AND account_id = $2",
            ).bind(&workspace).bind(id).fetch_one(&db).await?;
            assert_eq!(second.0, 2, "on-demand requests bypass cooldown");
            assert!((110.0..=120.0).contains(&second.1));

            sqlx::query("UPDATE mcp_oauth_refresh_state SET failure_count = 32, next_attempt_at = now() - interval '1 second' WHERE workspace_id = $1")
                .bind(&workspace).execute(&db).await?;
            let mut held = db.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(1464683843, $1)").bind(id).execute(&mut *held).await?;
            tokio::time::timeout(std::time::Duration::from_secs(2), refresh_mcp_account_background(path, &workspace, id, &db)).await??;
            held.rollback().await?;
            assert!(refresh_mcp_account_background(path, &workspace, id, &db).await.is_err());
            let capped: (i32, f64) = sqlx::query_as(
                "SELECT failure_count, extract(epoch FROM next_attempt_at - clock_timestamp())::float8
                 FROM mcp_oauth_refresh_state WHERE workspace_id = $1 AND account_id = $2",
            ).bind(&workspace).bind(id).fetch_one(&db).await?;
            assert_eq!(capped.0, 32);
            assert!((3590.0..=3600.0).contains(&capped.1));

            sqlx::query("UPDATE account SET expires_at = now() + interval '1 hour' WHERE workspace_id = $1 AND id = $2")
                .bind(&workspace).bind(id).execute(&db).await?;
            assert_eq!(_refresh_token(path, &workspace, id, &db, false).await?, "recovered");
            let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_oauth_refresh_state WHERE workspace_id = $1")
                .bind(&workspace).fetch_one(&db).await?;
            assert_eq!(remaining, 0, "successful on-demand reads clear retry state");
            Ok(())
        }.await;
        sqlx::query("DELETE FROM variable WHERE workspace_id = $1")
            .bind(&workspace)
            .execute(&db)
            .await?;
        sqlx::query("DELETE FROM account WHERE workspace_id = $1")
            .bind(&workspace)
            .execute(&db)
            .await?;
        sqlx::query("DELETE FROM workspace_key WHERE workspace_id = $1")
            .bind(&workspace)
            .execute(&db)
            .await?;
        sqlx::query("DELETE FROM workspace WHERE id = $1")
            .bind(&workspace)
            .execute(&db)
            .await?;
        result
    }
}
