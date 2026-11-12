-- Modified 2026-11-11: bound MCP OAuth background refresh and persist retry cooldowns.
CREATE TABLE mcp_oauth_refresh_state (
    workspace_id VARCHAR(50) NOT NULL,
    account_id INTEGER NOT NULL,
    failure_count INTEGER NOT NULL CHECK (failure_count BETWEEN 1 AND 32),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workspace_id, account_id),
    FOREIGN KEY (workspace_id, account_id) REFERENCES account (workspace_id, id) ON DELETE CASCADE
);

GRANT ALL ON mcp_oauth_refresh_state TO windmill_admin;

CREATE INDEX idx_account_mcp_refresh_due ON account (expires_at, id, workspace_id)
    WHERE client = 'mcp' AND refresh_token <> '';
CREATE INDEX idx_variable_oauth_account_secret ON variable (workspace_id, account, path)
    WHERE account IS NOT NULL AND is_secret;
