#!/usr/bin/env bash
# Modified 2026-11-12: persistent local AGPL builds, exclusively from public origin/main.
set -euo pipefail
REPO=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
PUBLIC=https://github.com/ynonp/windmill.git
STATE=${WINDMILL_BUILD_STATE:-$(dirname "$REPO")/.windmill-build}
HOST=${WINDMILL_DEPLOY_HOST:-root@89.58.35.113}
MODE=${1:-deploy}
[[ $# -le 1 && "$MODE" =~ ^(build|deploy)$ ]] || { echo "Usage: $0 [build|deploy] (always origin/main)" >&2; exit 1; }
[[ $(git -C "$REPO" remote get-url origin) == "$PUBLIC" ]] || { echo 'Unexpected origin' >&2; exit 1; }
mkdir -p "$STATE/logs" "$STATE/sources"
exec 9>"$STATE/build.lock"
flock -n 9 || { echo 'Another local Windmill build/deploy is running' >&2; exit 1; }
LOG="$STATE/logs/$(date -u +%Y%m%dT%H%M%SZ).log"
SOCKET="$STATE/tunnel-$$.sock"
trap 'ssh -S "$SOCKET" -O exit "$HOST" >/dev/null 2>&1 || true' EXIT

current_main() {
    git -C "$REPO" fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main
    git -C "$REPO" rev-parse refs/remotes/origin/main
}
image_matches() {
    podman image exists "$1" &&
    [[ $(podman image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$1") == "$REVISION" ]] &&
    [[ $(podman image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$1") == https://github.com/ynonp/windmill ]]
}
main() {
    local started=$SECONDS phase=$SECONDS
    REVISION=$(current_main)
    local src="$STATE/sources/$REVISION"
    echo "Building public origin/main: $REVISION"
    echo "Log: $LOG"
    if [[ ! -d "$src" ]]; then
        git init --quiet "$src"
        git -C "$src" fetch --quiet --depth=1 "$REPO" "$REVISION"
        git -C "$src" checkout --quiet --detach "$REVISION"
    fi
    [[ -z $(git -C "$src" status --porcelain) && $(git -C "$src" rev-parse HEAD) == "$REVISION" ]] || {
        echo "Build snapshot is dirty or has the wrong revision: $src" >&2; return 1;
    }
    local app="localhost/windmill-oss:$REVISION" slim="localhost/windmill-oss-slim:$REVISION" extra="localhost/windmill-oss-extra:$REVISION"
    local jobs=${CARGO_BUILD_JOBS:-4} stages=${BUILD_STAGES:-2}
    [[ "$jobs" =~ ^[1-9][0-9]*$ && "$stages" =~ ^[1-9][0-9]*$ ]] || return 1
    local -a labels=(--label "org.opencontainers.image.source=https://github.com/ynonp/windmill"
        --label "org.opencontainers.image.revision=$REVISION" --label org.opencontainers.image.licenses=AGPL-3.0-only)
    if ! image_matches "$app"; then
        podman build --layers --jobs "$stages" --format docker \
            --build-arg features=oss_core,all_languages,jemalloc \
            --build-arg "CARGO_BUILD_JOBS=$jobs" --build-arg DUCKDB_BUILD_JOBS=2 \
            --build-arg "WM_BUILD_VERSION=oss-$REVISION" \
            --build-arg "VITE_SOURCE_URL=https://github.com/ynonp/windmill/tree/$REVISION" \
            "${labels[@]}" -t "$app" -f "$src/Dockerfile" "$src"
    fi
    echo "TIMING application $((SECONDS-phase))s"; phase=$SECONDS
    if ! image_matches "$slim"; then
        podman build --layers --format docker --build-arg "BASE_IMAGE=$app" "${labels[@]}" \
            -t "$slim" -f "$src/docker/DockerfileSlim" "$src"
    fi
    if ! image_matches "$extra"; then
        podman build --layers --format docker --build-arg "BASE_IMAGE=$slim" "${labels[@]}" \
            -t "$extra" -f "$src/docker/DockerfileExtra" "$src"
    fi
    echo "TIMING slim-and-extra $((SECONDS-phase))s"; phase=$SECONDS
    image_matches "$app" && image_matches "$extra"
    echo "TIMING build-total $((SECONDS-started))s"
    [[ "$MODE" == deploy ]] || return 0
    [[ $(current_main) == "$REVISION" ]] || { echo 'origin/main advanced; rerun to build the latest commit' >&2; return 1; }
    local -a ssh_cmd=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=10 "$HOST")
    local port app_digest extra_digest
    port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=30 -o ServerAliveCountMax=10 -M -S "$SOCKET" -fN \
        -L "127.0.0.1:$port:127.0.0.1:5000" "$HOST"
    curl --fail --silent --show-error "http://127.0.0.1:$port/v2/" >/dev/null
    # The private loopback registry reuses unchanged layers; only SSH crosses the network.
    podman push --tls-verify=false --digestfile "$STATE/app.digest" "$app" "docker://127.0.0.1:$port/windmill-oss:$REVISION"
    podman push --tls-verify=false --digestfile "$STATE/extra.digest" "$extra" "docker://127.0.0.1:$port/windmill-oss-extra:$REVISION"
    app_digest=$(cat "$STATE/app.digest")
    extra_digest=$(cat "$STATE/extra.digest")
    echo "TIMING transfer $((SECONDS-phase))s"; phase=$SECONDS
    # Run the receiver from the same published snapshot as the images.
    "${ssh_cmd[@]}" "bash -s -- '$REVISION' '$app_digest' '$extra_digest'" < "$src/deploy/local-receive.sh"
    echo "TIMING deploy $((SECONDS-phase))s"
    echo "TIMING total $((SECONDS-started))s"
}
main 2>&1 | tee "$LOG"
