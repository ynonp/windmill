/*
 * Author: Windmill Labs, Inc
 * Copyright: Windmill Labs, Inc 2024
 * This file and its contents are licensed under the AGPLv3 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-AGPL for a copy of the license.
 */

//! MCP OAuth client registration and credential management.
//!
//! Handles dynamic client registration (DCR) and Client Identifier Metadata Document (CIMD)
//! flows for MCP OAuth, including caching registered credentials in the database.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use windmill_common::db::DB;
use windmill_common::error;
use windmill_common::variables::{build_crypt, decrypt, encrypt};

use crate::oauth::{no_redirect_http_client_pinned, AuthorizationManager};

#[derive(Deserialize)]
pub struct McpTokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[serde(
        default,
        deserialize_with = "windmill_common::more_serde::maybe_number_opt"
    )]
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
    pub token_type: String,
}

impl McpTokenResponse {
    pub fn validate(&self) -> error::Result<()> {
        if self.access_token.is_empty() || !self.token_type.eq_ignore_ascii_case("bearer") {
            return Err(error::Error::BadRequest(
                "MCP OAuth requires a Bearer access token".into(),
            ));
        }
        Ok(())
    }
}

pub async fn refresh_mcp_token(
    db: &DB,
    server_url: &str,
    refresh_token: &str,
    scopes: Option<&[String]>,
) -> error::Result<McpTokenResponse> {
    // A refresh grant belongs to its registered client; registering a replacement cannot renew it.
    let registered: McpOAuthClient = sqlx::query_as(
        "SELECT mcp_server_url, client_id, client_secret, client_secret_expires_at, token_endpoint FROM mcp_oauth_client WHERE mcp_server_url = $1",
    ).bind(server_url).fetch_optional(db).await?
        .filter(|client: &McpOAuthClient| !client.is_expired())
        .ok_or_else(|| error::Error::BadRequest("MCP OAuth client expired or missing; reconnect the server".into()))?;
    let credentials = registered.credentials(db).await?;
    let (client, endpoint) = credentials
        .token_request()
        .map_err(|_| error::Error::InternalErr("Failed to build MCP token client".into()))?;
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", credentials.client_id.as_str()),
        ("resource", server_url),
    ];
    let scope = scopes.unwrap_or_default().join(" ");
    if !scope.is_empty() {
        form.push(("scope", &scope));
    }
    if let Some(secret) = &credentials.client_secret {
        form.push(("client_secret", secret));
    }
    let response = client
        .post(endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|_| error::Error::BadRequest("MCP OAuth refresh request failed".into()))?;
    if !response.status().is_success() {
        return Err(error::Error::BadRequest(
            "MCP OAuth refresh was refused; reconnect the server".into(),
        ));
    }
    let token: McpTokenResponse = response
        .json()
        .await
        .map_err(|_| error::Error::BadRequest("Invalid MCP OAuth refresh response".into()))?;
    token.validate()?;
    Ok(token)
}

/// MCP client credentials returned by [`get_or_refresh_mcp_client`].
pub struct McpClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// The token endpoint and the addresses it resolved to during SSRF validation.
    /// Both are private so that [`Self::token_request`] is the only way to obtain
    /// the URL: it returns it together with a client pinned to those addresses, so
    /// no caller can post the `client_secret` to this URL on a client that
    /// re-resolves the host and lands somewhere else.
    token_endpoint: String,
    token_endpoint_target: windmill_common::ssrf::ValidatedTarget,
}

impl McpClientCredentials {
    /// The URL to post a token request to, together with a client pinned to the
    /// address that URL was validated against.
    pub fn token_request(&self) -> Result<(reqwest::Client, &str), reqwest::Error> {
        let client = no_redirect_http_client_pinned(&self.token_endpoint_target)?;
        Ok((client, self.token_endpoint.as_str()))
    }
}

#[derive(FromRow)]
struct McpOAuthClient {
    #[allow(dead_code)]
    mcp_server_url: String,
    client_id: String,
    client_secret: Option<String>,
    client_secret_expires_at: Option<chrono::NaiveDateTime>,
    token_endpoint: String,
}

impl McpOAuthClient {
    async fn credentials(self, db: &DB) -> error::Result<McpClientCredentials> {
        let token_endpoint_target = windmill_common::ssrf::validate_mcp_server_url_for_bad_request(
            &self.token_endpoint,
            "MCP server token endpoint URL",
        )
        .await?;
        let client_secret = match self.client_secret {
            Some(secret) => Some(decrypt_client_secret(db, &secret).await?),
            None => None,
        };
        Ok(McpClientCredentials {
            client_id: self.client_id,
            client_secret,
            token_endpoint: self.token_endpoint,
            token_endpoint_target,
        })
    }

    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.client_secret_expires_at {
            expires_at < chrono::Utc::now().naive_utc()
        } else {
            false
        }
    }
}

async fn encrypt_client_secret(db: &DB, client_secret: &str) -> error::Result<String> {
    let mc = build_crypt(db, "admins").await?;
    Ok(encrypt(&mc, client_secret))
}

async fn decrypt_client_secret(db: &DB, encrypted_secret: &str) -> error::Result<String> {
    let mc = build_crypt(db, "admins").await?;
    decrypt(&mc, encrypted_secret.to_string())
}

#[derive(Serialize)]
struct DcrRequest {
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
}

#[derive(Deserialize)]
struct DcrResponse {
    client_id: String,
    client_secret: Option<String>,
    client_secret_expires_at: Option<i64>,
}

async fn register_client(
    registration_endpoint: &str,
    redirect_uri: &str,
    client_name: &str,
) -> Result<DcrResponse, error::Error> {
    let validated = windmill_common::ssrf::validate_mcp_server_url_for_bad_request(
        registration_endpoint,
        "MCP server registration endpoint URL",
    )
    .await?;

    // Pin to the validated address: DCR posts to an author-controlled endpoint,
    // so the connect must not rebind to an internal IP after the check.
    let client = no_redirect_http_client_pinned(&validated)
        .map_err(|e| error::Error::BadRequest(format!("Failed to build DCR client: {e}")))?;
    let request = DcrRequest {
        client_name: client_name.to_string(),
        redirect_uris: vec![redirect_uri.to_string()],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types: vec!["code".to_string()],
        token_endpoint_auth_method: "none".to_string(),
    };

    let response = client
        .post(registration_endpoint)
        .json(&request)
        .send()
        .await
        .map_err(|e| error::Error::BadRequest(format!("DCR request failed: {e}")))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(error::Error::BadRequest(format!(
            "DCR failed: {error_text}"
        )));
    }

    response
        .json::<DcrResponse>()
        .await
        .map_err(|e| error::Error::BadRequest(format!("DCR response parse failed: {e}")))
}

/// Get MCP client credentials from cache, re-registering if expired.
///
/// Supports two modes:
/// - DCR (Dynamic Client Registration): If the server's metadata includes a registration endpoint
/// - CIMD (Client Identifier Metadata Document): Otherwise, uses our metadata URL as client_id
pub async fn get_or_refresh_mcp_client(
    db: &DB,
    mcp_server_url: &str,
) -> Result<McpClientCredentials, error::Error> {
    let base_url = (**windmill_common::BASE_URL.load()).clone();
    let redirect_uri = format!("{}/api/mcp/oauth/callback", base_url);

    let validated_server = windmill_common::ssrf::validate_mcp_server_url_for_bad_request(
        mcp_server_url,
        "MCP server URL",
    )
    .await?;

    let cached_client: Option<McpOAuthClient> =
        sqlx::query_as("SELECT mcp_server_url, client_id, client_secret, client_secret_expires_at, token_endpoint FROM mcp_oauth_client WHERE mcp_server_url = $1")
            .bind(mcp_server_url)
            .fetch_optional(db)
            .await
            .map_err(|e| error::Error::InternalErr(format!("Database error: {e}")))?;

    if let Some(client) = cached_client {
        if !client.is_expired() {
            tracing::debug!("Using cached MCP client for {}", mcp_server_url);
            return client.credentials(db).await;
        }
        tracing::debug!("Cached MCP client expired, re-registering");
    }

    let mut manager = AuthorizationManager::new(mcp_server_url)
        .await
        .map_err(|e| error::Error::BadRequest(format!("Failed to create auth manager: {e}")))?;
    // Discovery hits the well-known endpoint on the MCP server host validated
    // above; pin to that address so it cannot rebind between check and connect.
    // Limitation: rmcp's resolve_metadata may additionally follow server-supplied
    // metadata URLs (resource_metadata / authorization_servers) on other hosts,
    // which this per-host pin does not cover — a pre-existing gap in rmcp discovery
    // that a validating resolver would need to close, out of scope for this pin.
    let discovery_client = no_redirect_http_client_pinned(&validated_server).map_err(|e| {
        error::Error::BadRequest(format!("Failed to build MCP OAuth discovery client: {e}"))
    })?;
    manager
        .with_client(discovery_client)
        .map_err(|e| error::Error::BadRequest(format!("Failed to configure auth manager: {e}")))?;

    let metadata = crate::oauth::discover_authorization_metadata(&manager)
        .await
        .map_err(|e| error::Error::BadRequest(format!("OAuth discovery failed: {e}")))?;

    let token_endpoint_target = windmill_common::ssrf::validate_mcp_server_url_for_bad_request(
        &metadata.token_endpoint,
        "MCP server token endpoint URL",
    )
    .await?;

    let supports_dynamic_registration = metadata.registration_endpoint.is_some();

    let (client_id, client_secret, expires_at) = if supports_dynamic_registration {
        let reg_endpoint = metadata.registration_endpoint.as_ref().unwrap();
        tracing::debug!("Performing DCR at {}", reg_endpoint);
        let dcr = register_client(reg_endpoint, &redirect_uri, "Windmill").await?;

        let expires_at = dcr.client_secret_expires_at.and_then(|ts| {
            if ts == 0 {
                None
            } else {
                chrono::DateTime::from_timestamp(ts, 0).map(|dt| dt.naive_utc())
            }
        });

        (dcr.client_id, dcr.client_secret, expires_at)
    } else {
        let client_metadata_url = format!("{}/api/mcp/oauth/client-metadata.json", base_url);
        tracing::debug!(
            "Using CIMD with metadata URL as client_id: {}",
            client_metadata_url
        );

        (client_metadata_url, None, None)
    };

    let encrypted_secret = if let Some(ref secret) = client_secret {
        Some(encrypt_client_secret(db, secret).await?)
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO mcp_oauth_client (mcp_server_url, client_id, client_secret, client_secret_expires_at, token_endpoint)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (mcp_server_url) DO UPDATE
         SET client_id = EXCLUDED.client_id,
             client_secret = EXCLUDED.client_secret,
             client_secret_expires_at = EXCLUDED.client_secret_expires_at,
             token_endpoint = EXCLUDED.token_endpoint",
    )
    .bind(mcp_server_url)
    .bind(&client_id)
    .bind(&encrypted_secret)
    .bind(expires_at)
    .bind(&metadata.token_endpoint)
    .execute(db)
    .await
    .map_err(|e| error::Error::InternalErr(format!("Database error: {e}")))?;

    Ok(McpClientCredentials {
        client_id,
        client_secret,
        token_endpoint: metadata.token_endpoint,
        token_endpoint_target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_token_response_accepts_string_expiry_and_requires_bearer() {
        let token: McpTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "access", "token_type": "bearer", "expires_in": "0"
        }))
        .unwrap();
        assert_eq!(token.expires_in, Some(0));
        assert!(token.validate().is_ok());
        let unsupported: McpTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "access", "token_type": "mac"
        }))
        .unwrap();
        assert!(unsupported.validate().is_err());
    }
    use std::{
        io::{ErrorKind, Read},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    /// The whole SSRF fix rests on the pin actually diverting the connect: the
    /// token URL's host must never be resolved at connect time. `.invalid` is
    /// guaranteed not to resolve (RFC 6761), so the request can only arrive at
    /// the listener if it went to the pinned address.
    ///
    /// The accept loop is bounded so that a pin which stops working fails this
    /// test in seconds rather than blocking on `accept` forever.
    #[tokio::test]
    async fn token_request_connects_to_the_pinned_address_not_the_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0u8; 256];
                        stream.set_read_timeout(Some(Duration::from_secs(1))).ok();
                        let read = stream.read(&mut buffer).unwrap_or(0);
                        return Some(String::from_utf8_lossy(&buffer[..read]).to_string());
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => return None,
                }
            }
            None
        });

        let credentials = McpClientCredentials {
            client_id: "id".to_string(),
            client_secret: None,
            token_endpoint: "http://unresolvable.invalid/token".to_string(),
            token_endpoint_target: windmill_common::ssrf::ValidatedTarget {
                host: "unresolvable.invalid".to_string(),
                addrs: vec![addr],
            },
        };

        let (client, token_url) = credentials.token_request().unwrap();
        assert_eq!(token_url, "http://unresolvable.invalid/token");
        let _ = client.post(token_url).send().await;

        let request = handle
            .join()
            .unwrap()
            .expect("pinned address should have received the token POST");
        assert!(
            request.contains("/token") && request.contains("unresolvable.invalid"),
            "pinned socket should receive the token POST, got: {request}"
        );
    }
}
