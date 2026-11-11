# Production deployment

Modified 2026-11-11. `.github/workflows/deploy-oss.yml` deploys each push to
`main` in https://github.com/ynonp/windmill. Manual reruns are also supported on
main. Runs are serialized; a superseded commit is never deployed.

GitHub-hosted Ubuntu builds the published commit, using only
`oss_core,all_languages,jemalloc`. It publishes application, slim, and extra
images to `ghcr.io/ynonp/windmill-oss`, `windmill-oss-slim`, and
`windmill-oss-extra`. All are tagged with the complete commit SHA. Slim and
extra use our own base images pinned by digest. The frontend Source code link
points to the same public commit. Build instructions and the deployment
receiver are included here in the public source.

Production pulls immutable image digests, verifies their source and revision
labels, backs up PostgreSQL and `.env`, then runs Docker Compose. The database
and existing volumes are retained. The GitHub token is used for pulls through
a temporary Docker config, removed after deployment. No persistent GHCR
credential is stored on production.

## One-time setup and key rotation

Repository Actions secrets:

- `WINDMILL_DEPLOY_SSH_KEY`: dedicated Ed25519 private key.
- `WINDMILL_DEPLOY_KNOWN_HOSTS`: verified Ed25519 host key for `89.58.35.113`.

Install `github-deploy.sh` as `/opt/windmill/github-deploy.sh`, owned by root,
mode 700. Authorize only the public deployment key in `/root/.ssh/authorized_keys`
with `restrict,command="/opt/windmill/github-deploy.sh"`. This key permits only
`check` or the validated deployment command, without forwarding or an interactive
shell. The host uses the existing `/opt/windmill/compose.yaml` and `.env`.
Server requirements: Bash, Python 3, curl, gzip, flock, Docker and Compose.

When changing the receiver, review and install it through the administrator's
regular SSH key before publishing a workflow that needs the new protocol.
The Actions key cannot install arbitrary shell commands. To rotate the key,
install the new restricted public key, update the repository secret, test
`ssh ... check`, then remove the old public key. Never commit either private
keys or production environment files.

## Failure and recovery

The first cold Rust build can take several hours. Actions has a six-hour limit
and uses BuildKit layer caching; a failed build does not change production.
Inspect the Deploy AGPL Windmill workflow run for build and deployment logs.

Backups live under `/root/backups/windmill-<UTC timestamp>-<commit>.sql.gz`,
with the corresponding `.env` backup alongside. A failed deployment after
startup may already have applied migrations: do not automatically swap back to
older images. Restore the database and matching environment backup together
when a downgrade requires it. Database backups remain on the host; keep a
separate off-host backup as part of normal operations.

Existing parent-workspace deployment scripts are a manual alternative. To
ensure routine production changes always come from published source, use
this workflow for deployments.
