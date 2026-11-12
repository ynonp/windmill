# Local production build and deployment

Modified 2026-11-12. Builds and deployments run on the development box, not
GitHub Actions. Public source: https://github.com/ynonp/windmill.

## Daily workflow

Commit and push intended changes to `origin/main`, then from the fork run:

```sh
bash deploy/local.sh build    # build only, without changing production
bash deploy/local.sh deploy   # reuse/build images, transfer, back up, deploy
```

The parent workspace's `deploy/build.sh` and `deploy/deploy.sh` are wrappers.
Neither accepts a tag, another branch, `SRC`, or a working-tree build. Both
fetch `origin/main` and pin its exact commit. A dirty development checkout is
left untouched and never becomes the build context. Snapshots are checked for
cleanliness and reused. Before deployment, local and production both verify
that the commit is still public main; rerun if main advances.

Images are tagged `localhost/windmill-oss:<full SHA>`,
`localhost/windmill-oss-slim:<SHA>`, and `localhost/windmill-oss-extra:<SHA>`.
Only our AGPL `oss_core,all_languages,jemalloc` features are used. Slim and extra
use our own base images. Source/revision labels and Help → Source code refer
to the same published commit, including these build instructions.

## Persistent builder and performance

Podman/Buildah is the persistent build engine; no disposable CI daemon or host
Rust installation is used. Run as the same OS user every time. It retains:

- Intermediate image layers in existing Podman storage.
- `wm-cargo-registry`, `wm-cargo-git`, `wm-npm` build cache mounts.
- Separate `wm-rust-release` and `wm-duckdb-release` Cargo target cache mounts.
- Separate `wm-rust-sccache` and `wm-duckdb-sccache` compiler caches (30 GB each).
- Extra-image Go module/compiler, uv, pip and npm caches, reused after base-image changes.

Release targets survive source changes; layers retain stable tools and runtime
packages. Binaries are copied out of cache mounts before image assembly. Thin
LTO and mold remain enabled; Cargo incremental compilation is disabled for
sccache compatibility. Production CPU settings remain portable.

Defaults on this shared 12-vCPU, 31-GiB box are four Cargo jobs, two DuckDB jobs,
two parallel stages and a 4-GiB frontend Node heap. Tune with adequate available
RAM: `CARGO_BUILD_JOBS=6 BUILD_STAGES=1 bash deploy/local.sh build`. No other
services or builds are stopped. The first full build can be substantially slower
than the 15–20 minute warm-build target. Phase timings provide the benchmark.

State defaults to `<parent of fork>/.windmill-build/`:

- `sources/<SHA>/`: clean detached snapshots.
- `logs/<UTC timestamp>.log`: output and phase timings.
- `build.lock`: rejects simultaneous local builds/deploys.

Override with `WINDMILL_BUILD_STATE` on persistent disk, not RAM-backed `/tmp`.
Do not run `podman system prune` or delete build cache mounts routinely. Removing
old snapshots/logs does not remove compiler caches. Preserve images and volumes
used by other projects.

## Transfer and production verification

Prerequisites: Bash, Git, Podman, Python 3, curl, flock, tee and SSH on the build box;
Docker Compose, Bash, Python 3, curl, gzip and flock on production. The normal
administrator SSH key must work with strict host verification. Production's
Ed25519 fingerprint is `SHA256:HjuuuBHp9OhiAsioEZgNigqdt1Bdwyj4VRYbpFMo2Ss`.
Default destination: `root@89.58.35.113`; override with `WINDMILL_DEPLOY_HOST`.

An SSH tunnel binds an ephemeral local loopback port to production's existing
`127.0.0.1:5000` registry. Podman pushes only missing layers, then production
pulls by the exact returned manifest digests and verifies source/revision labels.
HTTP registry traffic stays on loopback or inside SSH. No GitHub token or
registry password is needed. `local-receive.sh` is streamed from the snapshot;
no separately installed receiver can drift from the image's source revision.

The receiver takes `/opt/windmill/.deploy.lock` (shared with the retired GitHub
receiver), verifies public main, backs up PostgreSQL and `.env`, atomically
updates image settings, starts Compose, verifies all application/extra image
refs and `/api/version`. Existing volumes and credentials stay on production.
After deployment, also exercise the changed functionality and verify the source
link. A successful build alone does not validate OAuth against a real provider.

## Failure and recovery

A build/transfer failure leaves production unchanged. Backup paths are printed
before switching: `/root/backups/windmill-<UTC>-<SHA>.sql.gz` and `.env`.
Migrations may have run if startup fails: restore the database and matching
environment together when a downgrade requires it. Never automatically switch
back across forward migrations. Keep off-host database backups separately.

The old `github-deploy.sh` and restricted key remain for historical recovery;
the Actions workflow was removed. Do not re-enable it alongside local deployment
without reviewing concurrency and source verification.
