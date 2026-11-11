#!/usr/bin/env bash
# Install as /opt/windmill/github-deploy.sh, root-owned and mode 700.
# Forced command for the dedicated GitHub Actions SSH key. Modified 2026-11-11.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [[ "${SSH_ORIGINAL_COMMAND:-}" == check ]]; then
  echo 'Windmill restricted deployment command ready'
  exit 0
fi
read -r -a args <<< "${SSH_ORIGINAL_COMMAND:-}"
if [[ ${#args[@]} != 5 || ${args[0]} != deploy ]]; then
  echo 'Only check or deploy <commit> <app digest> <extra digest> <actor> is allowed' >&2
  exit 1
fi
revision=${args[1]}
app_digest=${args[2]}
extra_digest=${args[3]}
actor=${args[4]}
[[ "$revision" =~ ^[a-f0-9]{40}$ ]]
[[ "$app_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "$extra_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "$actor" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}(\[bot\])?$ ]]

exec 9>/opt/windmill/.deploy.lock
flock -w 1800 9
# Verify anonymously: the source must be publicly available on main.
main_revision=$(curl --fail --silent --show-error --retry 3 \
  https://api.github.com/repos/ynonp/windmill/commits/main | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
[[ "$main_revision" == "$revision" ]] || { echo 'Revision is no longer public main; refusing stale deployment' >&2; exit 1; }

export DOCKER_CONFIG
DOCKER_CONFIG=$(mktemp -d /tmp/windmill-deploy-auth.XXXXXX)
trap 'rm -rf "$DOCKER_CONFIG"' EXIT
# Token arrives only on stdin and is removed with the temporary Docker config.
docker login ghcr.io -u "$actor" --password-stdin
app="ghcr.io/ynonp/windmill-oss@$app_digest"
extra="ghcr.io/ynonp/windmill-oss-extra@$extra_digest"
for image in "$app" "$extra"; do
  docker pull "$image"
  [[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")" == "$revision" ]]
  [[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$image")" == https://github.com/ynonp/windmill ]]
done

cd /opt/windmill
stamp="$(date -u +%Y%m%dT%H%M%SZ)-$revision"
install -d -m 700 /root/backups
backup="/root/backups/windmill-$stamp"
umask 077
docker compose exec -T db pg_dumpall -U postgres | gzip > "$backup.sql.gz"
gzip -t "$backup.sql.gz"
cp .env "$backup.env"
echo "Database and configuration backed up to $backup"

python3 - "$app" "$extra" <<'PY'
import os, pathlib, sys, tempfile
path = pathlib.Path('.env')
updates = dict(WM_IMAGE=sys.argv[1], WM_EXTRA_IMAGE=sys.argv[2])
lines = []
for line in path.read_text().splitlines():
    key = line.partition('=')[0]
    if key in updates:
        line = key + '=' + updates.pop(key)
    lines.append(line)
lines.extend(key + '=' + value for key, value in updates.items())
fd, name = tempfile.mkstemp(prefix='.env.', dir='.')
with os.fdopen(fd, 'w') as f:
    f.write('\n'.join(lines) + '\n')
os.replace(name, path)
PY
docker compose up -d --wait --wait-timeout 300
for service in windmill_server windmill_worker windmill_worker_native; do
  container=$(docker compose ps -q "$service")
  [[ -n "$container" ]]
  [[ "$(docker inspect --format '{{.Config.Image}}' "$container")" == "$app" ]]
done
for attempt in $(seq 1 30); do
  if curl --fail --silent --show-error --max-time 10 https://windmill.ynonperek.com/api/version; then
    printf '\nDeployed %s\nSource: https://github.com/ynonp/windmill/tree/%s\n' "$revision" "$revision"
    exit 0
  fi
  sleep 2
done
echo "Health check failed; backup: $backup. Restore DB before downgrading across migrations." >&2
exit 1
