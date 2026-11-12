use axum::{
    extract::Query,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;
use windmill_api_auth::{ApiAuthed, Tokened};
use windmill_common::{
    auth::hash_token,
    db::DB,
    error::{self, Error, JsonResult},
};
use windmill_mcp::{
    client_registration::get_or_refresh_mcp_client,
    oauth::{
        discover_authorization_metadata, no_redirect_http_client_pinned, AuthorizationManager,
        CsrfToken, PkceCodeChallenge,
    },
};

const CALLBACK_PATH: &str = "/api/mcp/oauth/callback";
const FLOW_LIFETIME: i64 = 600;

pub fn spawn_refresh_loop(db: DB, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = interval.tick() => {},
            }
            if let Err(error) = refresh_due_accounts(&db).await {
                tracing::warn!("MCP OAuth background refresh failed: {error}");
            }
        }
    });
}

async fn refresh_due_accounts(db: &DB) -> error::Result<()> {
    use futures::{stream, StreamExt};
    sqlx::query("DELETE FROM mcp_oauth_pending_flow WHERE expires_at <= now()")
        .execute(db)
        .await?;
    let accounts: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT a.workspace_id, a.id, v.path
         FROM account a
         JOIN LATERAL (
             SELECT path FROM variable
             WHERE account = a.id AND workspace_id = a.workspace_id AND is_secret
             ORDER BY path LIMIT 1
         ) v ON true
         LEFT JOIN mcp_oauth_refresh_state s ON s.workspace_id = a.workspace_id AND s.account_id = a.id
         WHERE a.client = 'mcp' AND a.expires_at <= now() AND a.refresh_token <> ''
           AND (s.next_attempt_at IS NULL OR s.next_attempt_at <= now())
         ORDER BY a.expires_at, a.id, a.workspace_id
         LIMIT 100",
    )
    .fetch_all(db)
    .await?;
    stream::iter(accounts)
        .for_each_concurrent(4, |(workspace, id, path)| async move {
            if windmill_store::oauth_refresh_oss::refresh_mcp_account_background(
                &path, &workspace, id, db,
            )
            .await
            .is_err()
            {
                tracing::warn!(account_id = id, "MCP OAuth account could not be refreshed");
            }
        })
        .await;
    Ok(())
}

pub fn global_service() -> Router {
    Router::new()
        .route("/discover", post(discover_mcp_oauth))
        .route("/start", get(start_mcp_oauth))
        .route("/callback", get(mcp_oauth_callback))
        .route("/client-metadata.json", get(get_client_metadata))
}

#[derive(Serialize)]
pub struct ClientMetadata {
    pub client_id: String,
    pub client_name: &'static str,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<&'static str>,
    pub response_types: Vec<&'static str>,
    pub token_endpoint_auth_method: &'static str,
}

pub async fn get_client_metadata() -> Json<ClientMetadata> {
    Json(ClientMetadata {
        client_id: format!(
            "{}/api/mcp/oauth/client-metadata.json",
            windmill_common::BASE_URL.load().trim_end_matches('/')
        ),
        client_name: "Windmill",
        redirect_uris: vec![callback_url()],
        grant_types: vec!["authorization_code", "refresh_token"],
        response_types: vec!["code"],
        token_endpoint_auth_method: "none",
    })
}

fn callback_url() -> String {
    format!(
        "{}{}",
        windmill_common::BASE_URL.load().trim_end_matches('/'),
        CALLBACK_PATH
    )
}

#[derive(Deserialize)]
pub struct DiscoverRequest {
    pub mcp_server_url: String,
}

#[derive(Serialize)]
pub struct DiscoverResponse {
    pub scopes_supported: Option<Vec<String>>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub supports_dynamic_registration: bool,
}

async fn discover(server_url: &str) -> error::Result<windmill_mcp::oauth::AuthorizationMetadata> {
    let target = windmill_common::ssrf::validate_mcp_server_url_for_bad_request(
        server_url,
        "MCP server URL",
    )
    .await?;
    let client = no_redirect_http_client_pinned(&target)
        .map_err(|_| Error::InternalErr("Failed to build OAuth discovery client".into()))?;
    let mut manager = AuthorizationManager::new(server_url)
        .await
        .map_err(|_| Error::BadRequest("Invalid MCP server URL".into()))?;
    manager
        .with_client(client)
        .map_err(|_| Error::InternalErr("Failed to configure OAuth discovery".into()))?;
    discover_authorization_metadata(&manager)
        .await
        .map_err(|_| Error::BadRequest("MCP server did not publish usable OAuth metadata".into()))
}

pub async fn discover_mcp_oauth(
    _authed: ApiAuthed,
    Json(req): Json<DiscoverRequest>,
) -> JsonResult<DiscoverResponse> {
    let metadata = discover(&req.mcp_server_url).await?;
    Ok(Json(DiscoverResponse {
        scopes_supported: metadata.scopes_supported,
        authorization_endpoint: metadata.authorization_endpoint,
        token_endpoint: metadata.token_endpoint,
        supports_dynamic_registration: metadata.registration_endpoint.is_some(),
        registration_endpoint: metadata.registration_endpoint,
    }))
}

#[derive(Deserialize)]
pub struct StartPopupParams {
    pub mcp_server_url: String,
    pub scopes: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PendingFlow {
    server_url: String,
    client_id: String,
    verifier: String,
}

fn browser_session_hash(cookies: &Cookies, token: &Tokened) -> error::Result<String> {
    if cookies
        .get("token")
        .is_some_and(|cookie| cookie.value() == token.token)
    {
        Ok(hash_token(&token.token))
    } else {
        Err(Error::BadRequest(
            "MCP OAuth requires a browser session".into(),
        ))
    }
}

pub async fn start_mcp_oauth(
    authed: ApiAuthed,
    token: Tokened,
    Extension(db): Extension<DB>,
    Extension(cookies): Extension<Cookies>,
    Query(params): Query<StartPopupParams>,
) -> Response {
    let result = match browser_session_hash(&cookies, &token) {
        Ok(session_hash) => start_flow(&db, &authed.email, &session_hash, params).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(redirect) => redirect.into_response(),
        Err(_) => popup_response(serde_json::json!({
            "type": "MCP_ERROR", "error": "Could not start OAuth. Check the server URL and try again."
        })),
    }
}

async fn start_flow(
    db: &DB,
    email: &str,
    session_hash: &str,
    params: StartPopupParams,
) -> error::Result<Redirect> {
    let valid_session: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM token WHERE token_hash = $1 AND email = $2
         AND label = 'session' AND (expiration IS NULL OR expiration > now()))",
    )
    .bind(session_hash)
    .bind(email)
    .fetch_one(db)
    .await?;
    if !valid_session {
        return Err(Error::BadRequest(
            "MCP OAuth requires a live browser session".into(),
        ));
    }
    let metadata = discover(&params.mcp_server_url).await?;
    windmill_common::ssrf::validate_mcp_server_url_for_bad_request(
        &metadata.authorization_endpoint,
        "MCP authorization endpoint",
    )
    .await?;
    let credentials = get_or_refresh_mcp_client(db, &params.mcp_server_url).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random().secret().to_owned();
    let mut url = url::Url::parse(&metadata.authorization_endpoint)
        .map_err(|_| Error::BadRequest("Invalid authorization endpoint".into()))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &credentials.client_id)
        .append_pair("redirect_uri", &callback_url())
        .append_pair("state", &state)
        .append_pair("code_challenge", challenge.as_str())
        .append_pair("code_challenge_method", "S256")
        .append_pair("resource", &params.mcp_server_url);
    let scopes = params
        .scopes
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !scopes.is_empty() {
        url.query_pairs_mut().append_pair("scope", &scopes);
    }
    let inserted = sqlx::query(
        "INSERT INTO mcp_oauth_pending_flow
            (state, session_token_hash, user_email, server_url, client_id, verifier, expires_at)
         SELECT $1, token_hash, email, $4, $5, $6, now() + $7 * interval '1 second'
         FROM token WHERE token_hash = $2 AND email = $3 AND label = 'session'
           AND (expiration IS NULL OR expiration > now())",
    )
    .bind(&state)
    .bind(session_hash)
    .bind(email)
    .bind(&params.mcp_server_url)
    .bind(&credentials.client_id)
    .bind(verifier.secret())
    .bind(FLOW_LIFETIME as f64)
    .execute(db)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(Error::BadRequest(
            "MCP OAuth session expired; connect again".into(),
        ));
    }
    Ok(Redirect::to(url.as_str()))
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
}

pub async fn mcp_oauth_callback(
    authed: ApiAuthed,
    token: Tokened,
    Extension(db): Extension<DB>,
    Extension(cookies): Extension<Cookies>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let result = match browser_session_hash(&cookies, &token) {
        Ok(session_hash) => complete_flow(&db, &authed.email, &session_hash, params).await,
        Err(error) => Err(error),
    };
    popup_response(match result {
        Ok(value) => value,
        Err(_) => serde_json::json!({
            "type": "MCP_ERROR", "error": "OAuth did not complete. Please connect again."
        }),
    })
}

async fn complete_flow(
    db: &DB,
    email: &str,
    session_hash: &str,
    params: CallbackParams,
) -> error::Result<serde_json::Value> {
    let invalid = || Error::BadRequest("Invalid or expired OAuth state".into());
    let flow = claim_flow(db, email, session_hash, &params.state).await?;
    if params.error.is_some() {
        return Err(Error::BadRequest("OAuth authorization was denied".into()));
    }
    let code = params.code.ok_or_else(invalid)?;
    let credentials = get_or_refresh_mcp_client(db, &flow.server_url).await?;
    if credentials.client_id != flow.client_id {
        return Err(Error::BadRequest(
            "OAuth client changed; connect again".into(),
        ));
    }
    let (client, endpoint) = credentials
        .token_request()
        .map_err(|_| Error::InternalErr("Failed to build OAuth token client".into()))?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("client_id", flow.client_id.as_str()),
        ("code_verifier", flow.verifier.as_str()),
        ("resource", flow.server_url.as_str()),
    ];
    let redirect = callback_url();
    form.push(("redirect_uri", &redirect));
    if let Some(secret) = &credentials.client_secret {
        form.push(("client_secret", secret));
    }
    let response = client
        .post(endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|_| Error::BadRequest("OAuth token exchange failed".into()))?;
    if !response.status().is_success() {
        return Err(Error::BadRequest(
            "OAuth provider refused the token exchange".into(),
        ));
    }
    let token: windmill_mcp::client_registration::McpTokenResponse = response
        .json()
        .await
        .map_err(|_| Error::BadRequest("Invalid OAuth token response".into()))?;
    token.validate()?;
    Ok(serde_json::json!({
        "type": "MCP_CONNECTED", "mcp_server_url": flow.server_url,
        "access_token": token.access_token, "refresh_token": token.refresh_token,
        "expires_in": token.expires_in, "scope": token.scope,
    }))
}

async fn claim_flow(
    db: &DB,
    email: &str,
    session_hash: &str,
    state: &str,
) -> error::Result<PendingFlow> {
    // Autocommit consumes the flow before any provider request, including failed exchanges.
    // A different session must neither claim nor invalidate the initiating session's flow.
    sqlx::query_as(
        "DELETE FROM mcp_oauth_pending_flow f USING token t
         WHERE f.state = $1 AND f.session_token_hash = $2 AND f.user_email = $3
           AND f.expires_at > now() AND t.token_hash = f.session_token_hash
           AND t.email = f.user_email AND t.label = 'session'
           AND (t.expiration IS NULL OR t.expiration > now())
         RETURNING f.server_url, f.client_id, f.verifier",
    )
    .bind(state)
    .bind(session_hash)
    .bind(email)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| Error::BadRequest("Invalid or expired OAuth state".into()))
}

fn popup_response(message: serde_json::Value) -> Response {
    // JSON is embedded in an HTML script, where a provider-controlled </script> must stay data.
    let payload = message
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let html = format!(
        r#"<!doctype html><html><head><title>MCP OAuth</title></head><body>
<p>You can close this window.</p><script>
if (window.opener) {{ window.opener.postMessage({payload}, window.location.origin); window.close(); }}
</script></body></html>"#
    );
    (
        [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ],
        Html(html),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a migrated development database"]
    async fn pending_flow_is_session_bound_and_consumed_once() -> anyhow::Result<()> {
        let db = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
        let session = hash_token(&uuid::Uuid::new_v4().to_string());
        let state = uuid::Uuid::new_v4().to_string();
        let email = "mcp-flow-test@example.invalid";
        sqlx::query(
            "INSERT INTO token (token_hash, token_prefix, label, email, expiration)
                     VALUES ($1, 'flow-test', 'session', $2, now() + interval '1 hour')",
        )
        .bind(&session)
        .bind(email)
        .execute(&db)
        .await?;
        let result: anyhow::Result<()> = async {
            sqlx::query("INSERT INTO mcp_oauth_pending_flow
                         (state, session_token_hash, user_email, server_url, client_id, verifier, expires_at)
                         VALUES ($1, $2, $3, 'https://example.invalid/mcp', 'client', 'secret', now() + interval '10 minutes')")
                .bind(&state).bind(&session).bind(email).execute(&db).await?;
            assert!(claim_flow(&db, email, "another-session", &state).await.is_err());
            assert!(claim_flow(&db, "another-user", &session, &state).await.is_err());
            sqlx::query("UPDATE mcp_oauth_pending_flow SET expires_at = now() - interval '1 second' WHERE state = $1")
                .bind(&state).execute(&db).await?;
            assert!(claim_flow(&db, email, &session, &state).await.is_err());
            sqlx::query("UPDATE mcp_oauth_pending_flow SET expires_at = now() + interval '10 minutes' WHERE state = $1")
                .bind(&state).execute(&db).await?;
            sqlx::query("UPDATE token SET expiration = now() - interval '1 second' WHERE token_hash = $1")
                .bind(&session).execute(&db).await?;
            assert!(claim_flow(&db, email, &session, &state).await.is_err());
            sqlx::query("UPDATE token SET expiration = now() + interval '1 hour' WHERE token_hash = $1")
                .bind(&session).execute(&db).await?;
            let (first, second) = tokio::join!(
                claim_flow(&db, email, &session, &state),
                claim_flow(&db, email, &session, &state),
            );
            assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
            assert!(claim_flow(&db, email, &session, &state).await.is_err());
            Ok(())
        }.await;
        sqlx::query("DELETE FROM token WHERE token_hash = $1")
            .bind(&session)
            .execute(&db)
            .await?;
        result
    }

    #[tokio::test]
    async fn popup_keeps_provider_values_inside_the_script_payload() {
        let response = popup_response(serde_json::json!({
            "access_token": "</script><script>alert('token')</script>"
        }));
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }
}
