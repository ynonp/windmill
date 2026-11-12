#!/usr/bin/env bash
# Modified 2026-11-12. Run over the administrator SSH connection by local.sh.
set -euo pipefail
[[ $# == 3 && "$1" =~ ^[a-f0-9]{40}$ && "$2" =~ ^[a-f0-9]{64}$ && "$3" =~ ^[a-f0-9]{64}$ ]] || exit 1
revision=$1
app="localhost/windmill-oss:$revision"
extra="localhost/windmill-oss-extra:$revision"
cd /opt/windmill
exec 9>.deploy.lock
flock -w 1800 9
main_revision=$(curl --fail --silent --show-error --retry 3 https://api.github.com/repos/ynonp/windmill/commits/main |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
[[ "$main_revision" == "$revision" ]] || { echo 'Public main advanced; refusing stale deployment' >&2; exit 1; }
for image in "$app" "$extra"; do
    [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image") == "$revision" ]]
    [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$image") == https://github.com/ynonp/windmill ]]
done
[[ $(docker image inspect --format '{{.Id}}' "$app") == "sha256:$2" ]]
[[ $(docker image inspect --format '{{.Id}}' "$extra") == "sha256:$3" ]]
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
for service in windmill_server windmill_worker windmill_worker_native windmill_extra; do
    container=$(docker compose ps -q "$service")
    expected=$app
    [[ "$service" != windmill_extra ]] || expected=$extra
    [[ -n "$container" && $(docker inspect --format '{{.Config.Image}}' "$container") == "$expected" ]]
done
curl --fail --silent --show-error --retry 5 --retry-delay 2 --max-time 15 https://windmill.ynonperek.com/api/version
printf '\nDeployed %s\nSource: https://github.com/ynonp/windmill/tree/%s\nBackup: %s\n' "$revision" "$revision" "$backup"
