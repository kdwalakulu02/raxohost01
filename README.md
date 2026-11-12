# raxohost

Small synchronous host/deployment agent for the raxo services. It installs
immutable, checksum-verified releases into a deploy root, switches them
atomically, restarts systemd services, runs health checks and rolls back
automatically when they fail. It also manages raxosentinel signature database
generations and renders/installs systemd unit files.

## Deploy root layout

```
<deploy_root>/                      (default /root/store01/deploy01)
  bin/raxohost -> ../current/raxohost/bin/raxohost
  releases/<project>/<release-id>/   unpacked release, read-only (dirs 0555, files 0444, bin/* 0555)
  current/<project> -> ../releases/<project>/<release-id>   swapped atomically
  config/<project>/                  runtime config/secrets (raxohost reads only config/raxohost/)
  config/raxohost/raxohost.toml      this tool's config
  config/raxohost/units/             unit templates
  data/<project>/                    persistent data; data/raxosentinel/rsidb/<generation>/ + current
  run/ logs/ backups/
  systemd/                           rendered units (copied to systemd_dir by `service install`)
  state/raxohost.json                active/previous/history per project and for the sentinel DB
  state/raxohost.lock                flock; concurrent raxohost runs are refused
```

Nothing at runtime references the build tree (`phase01/`); sources are only read at install time.

## Release sources

Each entry of `sources` is a local directory or an `https://` base URL laid out like
`phase01/dist/` (as produced by `tools/release.sh`):

```
<source>/<project>/<version>+<short>/
    <project>-<version>+<short>-<target>.tar.gz   single top dir with bin/, migrations/, manifest.json
    manifest.json                                 project, version, git_commit, ..., files[{path,sha256}]
    SHA256SUMS                                    sha256sum format, covers tarball (+ manifest.json)
<source>/raxosentinel-db/<generation>/
    <archive>.tar.gz   (./<generation>/database.rsidb ...)   manifest.json (database_file_sha256)   SHA256SUMS
```

The first source that has `SHA256SUMS` for the requested id is used. HTTPS sources can
publish `<project>/index.txt` (one id per line) so `release available` can list them.

Install procedure: fetch → verify archive against `SHA256SUMS` (and manifest.json if listed)
→ check the manifest matches `<project>` and `<version>+<commit[..7]>` → extract into a staging
dir inside `releases/<project>/` rejecting absolute paths, `..`, symlinks, hardlinks, devices,
duplicates and files not in the manifest → verify every `files[]` sha256 → make read-only →
`renameat2(RENAME_NOREPLACE)` into place. Installed releases are never modified.

Prebuilt archives (`"prebuilt": true` in the manifest, flat `./bin/...` layout, e.g.
`raxosentinel/0.1.0+38a6a14`) are supported: only files listed in the manifest are installed
(extra files such as `LICENSE`, `install-staging.sh` are skipped and reported) and the published
manifest.json is stored in the release dir.

## Commands

Global flags: `--config <path>` (or `RAXOHOST_CONFIG`), `--dry-run` (print what would happen,
change nothing, no lock), `--json` (status, release list/available/verify, sentineldb
list/available, health).

| Command | Description |
|---|---|
| `status [project]` | active/previous/installed releases, service states, sentinel DB generation |
| `release available [project]` | releases published in the sources |
| `release list [project]` | installed releases (`*` = active) |
| `release install <project> <id>` | fetch + verify + unpack (idempotent if already installed and valid) |
| `release verify <project> [id]` | re-verify installed files against the manifest (default: active) |
| `release activate <project> <id> [--no-restart]` | swap `current/<project>`, restart services, health check, auto-rollback |
| `release rollback <project> [--no-restart]` | activate the previous release |
| `release prune <project> --keep N --yes` | delete releases except active, previous and the N most recently installed |
| `deploy <project> <id> [--no-restart]` | install (if needed) + activate |
| `sentineldb install <generation>` | verify archive + `database.rsidb` sha256, unpack to `data/raxosentinel/rsidb/<generation>` (0700/0600, chown `sentineldb.owner`) |
| `sentineldb activate <generation> [--no-restart]` | atomically rewrite `rsidb/current`, restart sentinel services, health check, auto-rollback |
| `sentineldb rollback` / `list` / `available` | previous generation / installed / published |
| `service install` | render templates into `<deploy_root>/systemd/`, copy changed ones to `systemd_dir`, `daemon-reload`, `enable` configured units; prints new/changed/unchanged |
| `service render` | only render into `<deploy_root>/systemd/` and show the diff against `systemd_dir` |
| `service start\|stop\|restart\|status <name\|all>` | systemctl wrappers (`all` = every configured service) |
| `service logs <name\|all> [-n N] [--follow]` | journalctl wrapper |
| `health [project]` | run health checks once (exit 1 on failure) |
| `doctor` | layout, permissions, config, current symlinks, release verification, sentinel DB, units up to date, disk space |
| `self install <id>` | deploy the `raxohost` project and point `bin/raxohost` at `current/raxohost/bin/raxohost` |

Mutating commands take an exclusive lock on `state/raxohost.lock`.

### Activation and auto-rollback

1. The release is re-verified; a tampered release is refused.
2. A temporary symlink `current/.<project>.tmp-<pid>` is created and renamed over `current/<project>`.
3. `state/raxohost.json` records active/previous/timestamps/history.
4. The project's `services` are restarted in order, then health checks run with
   `health_retries` attempts every `health_interval_secs`.
5. On failure the previous release is re-activated the same way, services restarted again,
   the state restored (history gets an `auto-rollback` entry) and raxohost exits non-zero.

Sentinel DB activation follows the same steps with the `rsidb/current` file (temp file +
fsync + rename) instead of a symlink. raxosentinel reads it with
`--private-db-root <deploy_root>/data/raxosentinel/rsidb --private-generation current`.

## Configuration

See [`examples/raxohost.toml`](examples/raxohost.toml) (fully commented). Summary:

```toml
deploy_root = "/root/store01/deploy01"
sources = ["/root/store01/phase01/dist"]          # or "https://..."
# systemd_dir = "/etc/systemd/system"
# units_dir = "<deploy_root>/config/raxohost/units"
enable = ["raxo.target"]
health_retries = 10
health_interval_secs = 2

[projects.raxoemailrust]
services = ["raxo-api.service", "raxo-worker.service"]
health = [
  { type = "unit", unit = "raxo-api.service" },
  { type = "http", url = "http://127.0.0.1:8080/health/ready", timeout_secs = 5 },
  { type = "socket", path = "{{run:raxosentinel}}/scan.sock", mode = "0660", group = "raxoscan" },
  { type = "command", argv = ["{{current:raxoemailrust}}/bin/raxo-cli", "--help"] },
]

[sentineldb]
owner = "raxosentinel:raxosentinel"
# root, services, health default to data/raxosentinel/rsidb and [projects.raxosentinel]
```

Unknown keys are rejected. The `raxohost` project is implicit (no services).

### Sentinel socket access

The raxosentinel coordinator binds `<deploy_root>/run/raxosentinel/scan.sock`, chmods it to
0600 and forces its directory to 0700 (both owned by the scanner, UID 994 `raxosentinel`).
`examples/units/raxosentinel.service` therefore:

- creates the run dir as root in `ExecStartPre` (`install -d -o raxosentinel -g raxoscan -m 0700`);
- passes `--authorized-uid 995` (peer UID check stays; only `raxoemail` is accepted);
- in `ExecStartPost` waits for the socket (and the coordinator's own 0600 chmod), then sets
  group `raxoscan` on dir + socket, dir 0710, socket 0660 (scanner remains owner).

`raxo-api.service` / `raxo-worker.service` run as `raxoemail` (UID 995) with
`SupplementaryGroups=raxoscan`, `After=`/`Wants=raxosentinel.service`, and
`SENTINEL_SOCKET=<deploy_root>/run/raxosentinel/scan.sock`. Both users must be members of
`raxoscan`; `/root`, `/root/store01` and the deploy dirs must be traversable (0711).
The socket health check with `mode`/`group` verifies the fix-up after every activation.

### Unit templates

`*.service`, `*.target`, `*.timer`, `*.socket` files in `units_dir`; placeholders:

| Placeholder | Expands to |
|---|---|
| `{{deploy_root}}` | `<deploy_root>` |
| `{{current:<p>}}` | `<deploy_root>/current/<p>` (stable symlink path) |
| `{{data:<p>}}` / `{{config:<p>}}` / `{{run:<p>}}` / `{{logs:<p>}}` | `<deploy_root>/{data,config,run,logs}/<p>` |

Unknown placeholders are errors. Example templates are in [`examples/units/`](examples/units/).
The same placeholders work in health check `url`, `path` and `argv`.

## Typical session

```sh
raxohost release available
raxohost deploy raxosentinel 0.1.0+551fd35
raxohost sentineldb install phase2d6-unified && raxohost sentineldb activate phase2d6-unified
raxohost deploy raxoemailrust 0.1.0+1cbeea5
raxohost service install
raxohost status
raxohost release rollback raxoemailrust
raxohost self install 0.1.0+a52ccda
raxohost doctor
```

## Development

```sh
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
cargo build --release --locked
```

All systemctl/journalctl calls go through the `Systemd` trait (`src/systemd.rs`); the
integration tests (`tests/integration.rs`) use a fake implementation, build fake release
tarballs in temp dirs under `target/tmp`, and never touch the real system.
