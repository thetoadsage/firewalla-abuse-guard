# firewalla-abuse-guard

A small Python 3.12+ polling service: matching Firewalla MSP alarm → public remote
IP → AbuseIPDB check → Firewalla target list when `score >= block_threshold`.
Uses requests, PyYAML, and standard-library SQLite. Logs go to stdout.

Dry-run is the default. It performs API reads and writes local SQLite state,
but makes **no Firewalla writes**, including target-list creation. No UI,
notifications, alarm deletion, blacklist imports, or rule creation. In live mode,
successfully handled alarms are archived by default (`rules.archive_blocked`).

## Local setup

From this project directory:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
cp config.example.yml config.yml
chmod 600 config.yml
```

Edit `config.yml` with your MSP hostname (without `https://`), MSP personal access
token, box GID, and AbuseIPDB API key. Obtain the token in MSP Settings → MSP API;
find the box GID in MSP or using the MSP boxes API. Credentials belong only in
your local config; the git and Docker exclusions keep it out of source/builds.

```sh
firewalla-abuse-guard --config config.yml --once
firewalla-abuse-guard --config config.yml
```

`--once` returns nonzero on API/startup/state failure. The service retries API
failures on the next poll and handles SIGINT/SIGTERM. HTTP requests have bounded
connect/read timeouts, TLS verification, and no redirects. HTTP failures log
status codes without headers, response bodies, or credentials. A failed API call
ends the current cycle (including rate limits); tune the poll interval to your
API quota. SQLite errors stop the process instead of losing deduplication.

## Enable blocking

1. Review dry-run output (`would block` / `no action`) and adjust allowlists.
   Add your own public addresses and trusted remote services to the allowlist.
2. Firewalla requires at least one target when creating a list. For a new setup,
   stop continuous polling, set `rules.dry_run: false`, and run one poll with
   `--once`. The first qualifying alarm IP creates the **box-owned** list; further
   qualifying IPs are appended. No list is created if no IP meets the threshold.
   Do not seed the list with an unrelated placeholder IP. Professional/Business
   web-created lists may be MSP-owned, which this service deliberately ignores.
3. In the Firewalla app, open your box and go to Rules → Add Rule. Choose Block,
   then Target List → the configured list under Local. Choose the intended
   devices/network and schedule, then save. A target list alone does not enforce
   a block. This service does not create or verify firewall rules.
4. Start continuous polling again. For Docker, use
   `docker compose up -d --force-recreate` to reload the edited config.

Global lists with the same name are deliberately ignored. Duplicate names under
the selected box fail rather than selecting an arbitrary list. Updates read the
current targets and append the IP; existing entries remain. The MSP API uses
whole-array replacement, so run **one instance** and dedicate the list to this
service. Concurrent manual/API writers can race with read/modify/write updates.

To stop new additions, stop the service or restore dry-run. Previously added IPs
remain until you remove them in Firewalla; the service does not unblock addresses.

## Configuration and state

`config.example.yml` includes all options. Configuration is read at startup.

| Setting | Default | Meaning |
| --- | --- | --- |
| `rules.dry_run` | `true` | Read/check/log only |
| `rules.archive_blocked` | `true` | Archive alarms after all extracted remote IPs are added to the blocking list; live mode only |
| `rules.poll_interval_seconds` | `300` | Wait after each completed poll |
| `rules.lookback_hours` | `24` | Rolling alarm window, including the first run; 1–720 |
| `rules.ip_cache_hours` | `24` | Reuse AbuseIPDB scores for new matching alarms; 1–720 |
| `rules.alarm_keywords` | `["abnormal upload"]` | Case-insensitive substring matching on alarm labels/message |
| `abuseipdb.max_age_days` | `30` | Report age supplied to AbuseIPDB; 1–365 |
| `abuseipdb.block_threshold` | `90` | Inclusive score threshold; 0–100 |
| `state.path` | `data/state.sqlite3` | Relative to working directory or absolute |

All alarm pages in the window are fetched for the configured box. An outage
longer than the lookback window can leave older alarms unprocessed; increase the
window before restarting if needed. Both active and archived alarms in that
window can match. In live mode, `archive_blocked: true` archives an alarm only
after every extracted remote IP has been successfully added to the target list
or was previously added by this service and is confirmed still present. Alarms
with skipped/allowlisted or below-threshold IPs stay visible. A failed block or
archive request leaves the alarm retryable; successful IP additions persist so
an archive retry does not repeat blocking. Already archived alarms are not
archived again. Archiving does not mute future alarms or delete alarm history.
This endpoint requires MSP 2.11.0 or later. A 401/404 archive failure is logged
and retried, never replaced with deletion or muting.

Enabling archiving revisits previously processed alarms still in the lookback
window (24 hours by default), including alarms for IPs already added. Older
alarms are not swept automatically. As with blocking, the service relies on your
configured block rule to enforce target-list membership; it does not verify
rule scope or enforcement.

The default keyword also matches MSP numeric alarm type `2` (Abnormal Upload).
Remote extraction handles nested objects/lists and fields such as `remote.ip`,
`remoteIP`, `destination.address`, `dst_ip`, and `p.dest.ip`. Only IP literals in
recognized remote/destination address fields are used. Local/device/source/WAN
subtrees, generic IP fields, prose, URLs, and DNS resolution are excluded. Missing
remote fields on matching summaries trigger a details request. Unknown shapes
log `no recognized remote IP fields` and are marked processed; inspect and adjust
`logic.py` with a sanitized fixture if your MSP uses a different schema.

Non-global/private, loopback, multicast, reserved, link-local, unspecified,
IPv4-mapped IPv6, and allowlisted IPs are skipped before AbuseIPDB is called.

SQLite stores processed alarm IDs, cached score metadata, and successfully added
IPs. Alarm state is scoped to the box, target list, mode, and policy settings.
Switching dry-run to live or changing policy re-evaluates alarms still in the
window; cached scores can still be used. Dry-run never records an IP as blocked.
Failed checks/updates leave alarms unprocessed for retry. IPs already recorded as
added to that target list are not added again, even after cache expiry. Successful
remote writes are recorded locally afterward; if interrupted between these
steps, the next attempt checks existing target membership before writing.

There is no background score refresh, expiry-based unblock, list reconciliation,
or state pruning. Removing an IP/list manually does not clear its SQLite record.
To replay everything in the lookback window or reconcile after manual removal,
stop the service and select a fresh `state.path` (retain the old file as backup).
That also discards cached scores and can cause live additions again. Merely
expiring an IP cache does not reprocess an already completed alarm.

## Docker

```sh
cp config.example.yml config.yml
# Edit credentials and settings first; leave dry_run: true for the first run.
cp docker-compose.example.yml compose.yml
docker compose build
docker compose run --rm firewalla-abuse-guard --config /app/config.yml --once
docker compose up -d
docker compose logs -f
```

The image runs as UID/GID `10001:10001`, with a read-only root filesystem and a
named volume for `/app/data`. Keep `state.path: data/state.sqlite3` inside the
container. On Linux, ensure UID 10001 can read the bind-mounted config: for
example, `sudo chown 10001:10001 config.yml && sudo chmod 600 config.yml`.
Docker Desktop mount permissions may differ. The named volume persists across
container recreation; `docker compose down -v` removes it and all deduplication
state. No inbound ports are exposed.

## Tests and API adjustments

```sh
python -m unittest discover -s tests -v
```

Tests use fake API responses and temporary SQLite databases; no credentials or
network are needed. API paths, payloads, authentication, pagination, and response
adapters are isolated in `firewalla_abuse_guard/clients.py`. Adjust that file and
the matching fixtures after testing against your MSP. Unknown API shapes fail
rather than replacing a list with incomplete data. Live integration requires
your credentials and has not been verified by the unit tests.

API references used for this implementation:

- [Firewalla alarms](https://docs.firewalla.net/api-reference/alarm/)
- [Firewalla alarm schema](https://docs.firewalla.net/data-models/alarm/)
- [Firewalla searching and pagination](https://docs.firewalla.net/api-reference/search/)
- [Firewalla target lists](https://docs.firewalla.net/api-reference/target-lists/)
- [AbuseIPDB check API](https://docs.abuseipdb.com/#check-endpoint)
