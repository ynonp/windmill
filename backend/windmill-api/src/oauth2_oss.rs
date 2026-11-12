#[cfg(feature = "private")]
#[allow(unused)]
pub use crate::oauth2_ee::*;

/*
 * Author: Ruben Fiszel
 * Copyright: Windmill Labs, Inc 2022
 * This file and its contents are licensed under the AGPLv3 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-AGPL for a copy of the license.
 */

#[cfg(not(feature = "private"))]
use std::{collections::HashMap, fmt::Debug};

#[cfg(not(feature = "private"))]
use axum::{routing::get, Json, Router};
#[cfg(not(feature = "private"))]
use hmac::Mac;

#[cfg(all(feature = "oauth2", not(feature = "private")))]
use itertools::Itertools;
#[cfg(not(feature = "private"))]
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "oauth2", not(feature = "private")))]
use windmill_common::more_serde::maybe_number_opt;
#[cfg(all(feature = "oauth2", not(feature = "private")))]
use windmill_oauth::{helpers, AccessToken, RefreshToken, Scope};

#[cfg(all(feature = "oauth2", not(feature = "private")))]
use crate::OAUTH_CLIENTS;
#[cfg(not(feature = "private"))]
use windmill_common::error;
#[cfg(not(feature = "private"))]
use windmill_common::oauth2::*;

#[cfg(not(feature = "private"))]
use crate::db::DB;
#[cfg(not(feature = "private"))]
use std::str;

#[cfg(not(feature = "private"))]
pub fn global_service() -> Router {
    Router::new()
        .route("/list_logins", get(list_logins))
        .route("/list_connects", get(list_connects))
}

#[cfg(not(feature = "private"))]
pub fn workspaced_service() -> Router {
    let router = Router::new();
    #[cfg(feature = "oauth2")]
    return router
        .route("/create_account", axum::routing::post(create_mcp_account))
        .route("/refresh_token/{id}", axum::routing::post(refresh_account));
    #[cfg(not(feature = "oauth2"))]
    router
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
#[derive(Deserialize)]
struct CreateMcpAccount {
    client: String,
    refresh_token: String,
    expires_in: i64,
    mcp_server_url: String,
    scopes: Option<Vec<String>>,
    variable: windmill_common::variables::CreateVariable,
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
async fn create_mcp_account(
    authed: windmill_api_auth::ApiAuthed,
    axum::Extension(db): axum::Extension<DB>,
    axum::Extension(user_db): axum::Extension<windmill_common::db::UserDB>,
    axum::Extension(webhook): axum::Extension<windmill_common::webhook::WebhookShared>,
    axum::extract::Path(w_id): axum::extract::Path<String>,
    Json(mut request): Json<CreateMcpAccount>,
) -> error::JsonResult<Option<i32>> {
    if request.client != "mcp" || request.refresh_token.is_empty() || request.expires_in < 0 {
        return Err(error::Error::BadRequest(
            "Expected an MCP OAuth account with a refresh token".into(),
        ));
    }
    windmill_common::ssrf::validate_mcp_server_url_for_bad_request(
        &request.mcp_server_url,
        "MCP server URL",
    )
    .await?;
    request.variable.is_secret = true;
    request.variable.is_oauth = Some(true);
    let account = windmill_store::variables::NewOAuthAccount {
        client: request.client,
        refresh_token: Some(request.refresh_token),
        expires_in: request.expires_in,
        mcp_server_url: Some(request.mcp_server_url),
        scopes: request.scopes,
        grant_type: "authorization_code".into(),
        cc_client_id: None,
        cc_client_secret: None,
        cc_token_url: None,
    };
    Ok(Json(
        windmill_store::variables::create_variable_with_account(
            authed,
            &db,
            user_db,
            &webhook,
            w_id,
            request.variable,
            false,
            Some(account),
        )
        .await?,
    ))
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
#[derive(Deserialize)]
struct RefreshAccountRequest {
    path: String,
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
async fn refresh_account(
    authed: windmill_api_auth::ApiAuthed,
    axum::Extension(db): axum::Extension<DB>,
    axum::Extension(user_db): axum::Extension<windmill_common::db::UserDB>,
    axum::extract::Path((w_id, id)): axum::extract::Path<(String, i32)>,
    Json(request): Json<RefreshAccountRequest>,
) -> error::Result<String> {
    windmill_api_auth::check_scopes(&authed, || format!("variables:read:{}", request.path))?;
    let mut tx = user_db.begin(&authed).await?;
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM variable WHERE workspace_id = $1 AND path = $2 AND account = $3 AND is_secret)",
    ).bind(&w_id).bind(&request.path).bind(id).fetch_one(&mut *tx).await?;
    if !authorized {
        return Err(error::Error::NotFound(
            "OAuth token variable not found".into(),
        ));
    }
    windmill_audit::audit_oss::audit_log(
        &mut *tx,
        &authed,
        "variables.decrypt_secret",
        windmill_audit::ActionKind::Execute,
        &w_id,
        Some(&request.path),
        None,
    )
    .await?;
    tx.commit().await?;
    windmill_store::oauth_refresh_oss::_refresh_token(&request.path, &w_id, id, &db, false).await
}

#[cfg(not(feature = "private"))]
pub async fn workspace_connect_slack() -> Result<http::status::StatusCode, error::Error> {
    Err(error::Error::BadRequest(
        "Slack only available on enterprise".to_string(),
    ))
}

#[cfg(not(feature = "private"))]
pub async fn connect_slack_instance() -> Result<http::status::StatusCode, error::Error> {
    Err(error::Error::BadRequest(
        "Slack only available on enterprise".to_string(),
    ))
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
pub use windmill_oauth::{AllClients, BasicClientsMap, ClientWithScopes};

#[cfg(not(feature = "private"))]
pub use windmill_oauth::{OAuthClient, OAuthConfig};

#[cfg(all(feature = "oauth2", not(feature = "private")))]
pub async fn build_oauth_clients(
    _base_url: &str,
    _oauths_from_config: Option<HashMap<String, OAuthClient>>,
    _db: &DB,
) -> anyhow::Result<AllClients> {
    // Implementation is not open source
    return Ok(AllClients {
        logins: HashMap::default(),
        connects: HashMap::default(),
        slack: None,
        slack_signing_secret: None,
    });
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    access_token: AccessToken,
    #[serde(deserialize_with = "maybe_number_opt")]
    #[serde(default)]
    expires_in: Option<u64>,
    refresh_token: Option<RefreshToken>,
    #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
    #[serde(default)]
    scope: Option<Vec<Scope>>,
}

#[cfg(not(feature = "private"))]
#[derive(Serialize)]
struct Logins {
    oauth: Vec<String>,
    saml: Option<String>,
    auto_login: Option<String>,
}
#[cfg(not(feature = "private"))]
async fn list_logins() -> error::JsonResult<Logins> {
    // Implementation is not open source
    return Ok(Json(Logins { oauth: vec![], saml: None, auto_login: None }));
}

#[allow(unused)]
#[cfg(all(feature = "oauth2", not(feature = "private")))]
async fn list_connects() -> error::JsonResult<Vec<String>> {
    Ok(Json(
        (&OAUTH_CLIENTS.load().connects)
            .keys()
            .map(|x| x.to_owned())
            .collect_vec(),
    ))
}

#[allow(unused)]
#[cfg(not(all(feature = "oauth2", not(feature = "private"))))]
async fn list_connects() -> windmill_common::error::JsonResult<Vec<String>> {
    // Implementation is not open source
    return Ok(axum::Json(vec![]));
}

#[cfg(not(feature = "private"))]
pub async fn _refresh_token(
    path: &str,
    w_id: &str,
    id: i32,
    db: &DB,
    force: bool,
) -> error::Result<String> {
    #[cfg(feature = "oauth2")]
    return windmill_store::oauth_refresh_oss::_refresh_token(path, w_id, id, db, force).await;
    #[cfg(not(feature = "oauth2"))]
    Err(error::Error::BadRequest("Requires oauth2 feature".into()))
}

#[cfg(not(feature = "private"))]
pub async fn check_nb_of_user(db: &DB) -> error::Result<()> {
    let nb_users_sso =
        sqlx::query_scalar!("SELECT COUNT(*) FROM password WHERE login_type != 'password'",)
            .fetch_one(db)
            .await?;
    if nb_users_sso.unwrap_or(0) >= 10 {
        return Err(error::Error::BadRequest(
            "You have reached the maximum number of oauth users accounts (10) without an enterprise license"
                .to_string(),
        ));
    }

    let nb_users = sqlx::query_scalar!("SELECT COUNT(*) FROM password",)
        .fetch_one(db)
        .await?;
    if nb_users.unwrap_or(0) >= 50 {
        return Err(error::Error::BadRequest(
            "You have reached the maximum number of accounts (50) without an enterprise license"
                .to_string(),
        ));
    }
    return Ok(());
}

#[derive(Clone, Debug)]
#[cfg(not(feature = "private"))]
pub struct SlackVerifier {
    mac: HmacSha256,
}
#[cfg(not(feature = "private"))]
impl SlackVerifier {
    pub fn new<S: AsRef<[u8]>>(secret: S) -> anyhow::Result<SlackVerifier> {
        HmacSha256::new_from_slice(secret.as_ref())
            .map(|mac| SlackVerifier { mac })
            .map_err(|_| anyhow::anyhow!("invalid secret"))
    }

    pub fn verify(&self, ts: &str, body: &str, exp_sig: &str) -> anyhow::Result<()> {
        let basestring = format!("v0:{}:{}", ts, body);
        let mut mac = self.mac.clone();
        mac.update(basestring.as_bytes());
        let sig = format!("v0={}", hex::encode(mac.finalize().into_bytes()));
        if sig != exp_sig {
            Err(anyhow::anyhow!("signature mismatch"))?;
        }
        Ok(())
    }
}
