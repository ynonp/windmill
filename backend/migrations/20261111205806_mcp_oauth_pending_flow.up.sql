-- Modified 2026-11-11: keep MCP PKCE verifiers server-side and consume flows once.
CREATE TABLE mcp_oauth_pending_flow (
    state TEXT PRIMARY KEY,
    session_token_hash VARCHAR(64) NOT NULL REFERENCES token(token_hash) ON DELETE CASCADE,
    user_email TEXT NOT NULL,
    server_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    verifier TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX mcp_oauth_pending_flow_expiry ON mcp_oauth_pending_flow (expires_at);
CREATE INDEX mcp_oauth_pending_flow_session ON mcp_oauth_pending_flow (session_token_hash);
GRANT ALL ON mcp_oauth_pending_flow TO windmill_admin;
