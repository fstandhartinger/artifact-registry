# Artifact registry

A small authenticated registry of six-hex-digit artifact IDs. Store short descriptions
and source pointers, rather than copies of documents or sensitive data.

Run with Python 3.12 and PostgreSQL 16:

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
# Provision a dedicated database/role and apply migrations/001_init.sql as its owner.
# Supply ARTIFACTS_DATABASE_URL from your secret store.
.venv/bin/python registry.py
```

The service binds port 8080 (`PORT` / `ARTIFACTS_BIND` can override it). `/healthz`
returns only `{"ok":true}`. Every other route requires a bearer token. The `token`
table stores only SHA256 hashes with explicit scopes (see the scope matrix below).
Provision tokens through the database as an administrator; no token administration
endpoint is exposed. Use HTTPS at the reverse proxy.

API routes:

- GET `/v1/resolve?ids=a%23abcdef,card:123`, `/v1/exists?ids=abcdef`
- GET `/v1/search?q=reserve&surface=example&kind=panel&limit=50`
- GET `/v1/list?surface=example`, `/v1/dictionary`
- POST `/v1/ids` with `{ "count": 1, "surface": "example" }`
- POST `/v1/artifacts`, PUT `/v1/artifacts/abcdef`
- POST `/v1/sync` with `{ "surface": "example", "sync_source": "manifest", "generation": 1, "sha": "<commit>", "allow_shrink": true, "items": [] }`
- POST `/v1/dictionary` with `{ "term": "Example", "replace_from": [], "source": "manual" }`

IDs in responses have the display prefix `a#`; the database stores the hex part.
Resolve accepts canonical IDs case-insensitively and aliases, including bare legacy
card numbers. Unknown IDs are returned separately. Reserved IDs become visible once
upserted. Manifest retirement is source-scoped; see the v2 sync contract below. Ownership cannot
be transferred by an upsert. Writes, including full manifest retirement, are atomic and
audited; a single transaction lock prevents competing writers from taking ownership.
Reservations never expire.

`kind`, `title`, and `surface` are required for a new artifact. Existing IDs support
partial updates. `refs` replace refs from the same origin; `aliases` add permanent bindings.
Parents can appear after children in a manifest. All non-public summaries/titles reject
currency amounts with three or more digits; all titles/summaries reject likely secrets,
IBANs, and recovery phrases. The filter is conservative and cannot prove text is safe:
never submit sensitive content. References must not contain inline credentials.

Install `bin/artifact`, `bin/artifact_cli.py`, `bin/artifact_ids.py`, and
`bin/artifact-mcp` together in a PATH directory. CLI/MCP need only Python's standard
library; Pillow or ImageMagick is optional for `artifact stamp`.

```sh
artifact new --kind panel --title 'Reserve projection' --surface example \
  --summary 'Explains reserve assumptions.' --ref repo=github:example/project
artifact resolve a#abcdef --expand --json
artifact scan 'Read A # ABCDEF'
artifact dict add Jev --from Jeff
artifact dict import vocabulary.txt --source wispr
artifact stamp diagram.png --id a#abcdef
```

Configure `ARTIFACTS_URL` and `ARTIFACTS_AGENT_TOKEN` in the environment or
`~/.config/dev-secrets.env`. That file is parsed as data, never executed. Environment
values override it. HTTP is permitted only on loopback. The client refuses redirects
so bearer credentials cannot be forwarded to another host.

Expansion is local to the CLI/MCP caller: at most 80 lines / 12,000 characters per
reference. Code uses `gh api` at `pinned_sha`, or the revision in its pointer; files
are restricted to the caller's jobs, work, skills, and AGENTS.md, plus finance only for
private artifacts. Symlinks are resolved before checking roots. Board/decision/card
references use local tools and files. Obvious secrets are redacted. Never grant an
untrusted caller MCP expansion access: source pointers are untrusted content and the
caller's OS permissions still apply. Endpoint references are displayed, never fetched.

`artifact_ids.new_id()` produces an offline candidate only. Online callers allocate
IDs through the registry; OCR candidates from `find_ids()` must be confirmed via
`/v1/exists` before use.

Run `.venv/bin/python -m unittest` for the integration suite. It requires local
Postgres administrator access via passwordless `sudo -u postgres psql`, the dedicated
application role, and its DSN in the environment/secret store. It creates and drops
`artifacts_v2test`, refusing to touch an already-existing test database. Production
registry data is not modified. CLI module tests alone:

```sh
python -m unittest tests.test_ids
```

MCP uses newline-delimited JSON-RPC over stdio, protocol `2025-06-18`, and exports
`artifact_resolve`, `artifact_search`, `artifact_list`, and `artifact_upsert`.
Only protocol messages are written to stdout.

Pinned GitHub SHA existence is checked through the GitHub commit API with a shared
two-second budget per request and a bounded cache. Set optional `GITHUB_TOKEN` in
the service environment for private repo access; it is never returned or logged.
HTTP 200 confirms presence; HTTP 410 confirms absence. A 404 (which GitHub also
uses for inaccessible private repositories), rate limit, expired budget or network
failure is **unknown**, does not set `stale`, and is cached for one minute. Confirmed
results are cached for 15 minutes. Invalid `.`/`..` owner/repo segments are rejected
by the API and CLI before GitHub calls. Manifest age over seven days and explicit
`stale_reason` still mark an artifact stale independently.

Limitations: no pagination beyond the bounded list/search limit (200), CORS, or browser token
handling is provided; use an authenticated server-side gateway. Dictionary reads return
the full dictionary. Token surface restrictions apply to mutations; read scope still sees all surfaces.
Put proxy rate limits in front of the service. Invalid/missing or oversized bearer
headers are rejected before connecting to PostgreSQL; at most eight connections
are open per service process. At capacity requests receive 503. Authentication
results (including failures) are cached for 60 seconds, bounded to 4096 hashes;
revocation/scope/surface changes take up to 60 seconds or a process restart.
`stamp` writes a sibling `.stamped.png`, preserving the
input image. Docker deployment must copy the `data` directory for the recovery-phrase
filter. BIP39 word list attribution is in `data/README.md`.

## Registry v2

Apply `migrations/002_v2.sql` **after** `001_init.sql`, as the database owner.
The file includes `BEGIN`/`COMMIT`; use `psql -X -v ON_ERROR_STOP=1 -f
migrations/002_v2.sql` without an extra transaction wrapper. Before any DDL a
readable exception lists case-variant alias collisions. Failure rolls back every
change, including scope grants. It adds columns/tables, an alias index and an
immutability trigger. Existing v1 artifacts count as allocated; existing refs
acquire `origin=agent`. Existing mixed-case aliases remain readable.

The lead must first run this preflight **read-only** on live:

```sql
SELECT lower(alias) AS canonical_alias, count(*) AS bindings,
       array_agg(alias ORDER BY alias) AS aliases,
       array_agg(artifact_id ORDER BY alias) AS targets
FROM artifact_alias GROUP BY lower(alias) HAVING count(*) > 1;
```

If it returns rows, stop migration and review/export those bindings. An optional
v1 dedupe for collisions that **all point to the same artifact** follows; retain
the lowercase spelling when present, otherwise the first spelling. Run only after
review and backup, before migration 002 creates the immutability trigger:

```sql
BEGIN;
WITH ranked AS (
 SELECT alias, row_number() OVER (
   PARTITION BY lower(alias) ORDER BY (alias=lower(alias)) DESC, alias) AS n
 FROM artifact_alias
 WHERE lower(alias) IN (
   SELECT lower(alias) FROM artifact_alias GROUP BY lower(alias)
   HAVING count(*)>1 AND count(DISTINCT artifact_id)=1)
)
DELETE FROM artifact_alias a USING ranked r WHERE a.alias=r.alias AND r.n>1;
COMMIT;
```

This never reassigns a binding. Different-target collisions require an explicit
owner decision; do not automatically choose a winner. Rerun the preflight; proceed
only with zero rows. Take a database backup, pause writers, apply 002 with the
owner DSN, inspect scopes/surfaces, update CLI/sync callers, then start v2. Use the
new CLI or supply generation explicitly; all manifest IDs must be preallocated.
No existing token receives `admin` or `timer` from migration.

### Scopes and surface restrictions

| Operation | Required scope | Surface restriction |
| --- | --- | --- |
| Resolve, exists, list, search, GET verify-refs | `read` | Reads remain global |
| GET or POST dictionary | `dict` | Not surface-specific |
| Allocate IDs / pool refill, upsert, link, POST verify-refs | `write` | Artifact surface; links also check destination |
| POST sync, including retirement | `sync` | Entire requested surface |
| Write refs with `origin=timer` | `write` and `timer` | Artifact surface |
| POST admin/sync-reset | `admin` | Requested surface |

`token.surfaces` is optional `text[]`: NULL allows all surfaces, an empty array
allows no mutations, `['app:earnings*','notify']` allows the `app:earnings` prefix
and exact `notify`. Only a trailing `*` acts as a wildcard; other characters are
literal. The migration adds `sync` to tokens named exactly `sync` and `agent`,
retaining their existing scopes (including agent `write`). All other tokens keep
their scopes. A sync-only token cannot allocate IDs or do ordinary upserts;
provision `write` separately if its caller needs those operations. The lead may
bind tokens to surfaces during rollout; existing NULL restrictions preserve
compatibility. Grant `timer` only to a verification/ref timer that needs to own
refs; the verification timestamp endpoint itself only needs `write`.

The lead provisions an `admin` token separately. To recover a bad historical
generation, POST `/v1/admin/sync-reset` with
`{"surface":"app:example","sync_source":"components.json"}`. This deletes only
that source's generation checkpoint and audits the reset; artifacts and refs are
unchanged. Retry a reviewed manifest afterwards. `write` or `sync` alone cannot
reset state.

### Rollback to v1

There is no automatic down-migration. Stop v2 writers, restore v1 code/CLI, and
**drop the immutability trigger as database owner** before starting v1:

```sql
DROP TRIGGER IF EXISTS artifact_alias_immutable ON artifact_alias;
```

Without this step v1 alias delete/reinsert fails with `alias_taken`. Keep additive
columns/tables and the alias RESTRICT FK; v1 deletes alias rows before replacing
them. The lowercase index still refuses ambiguous aliases; dropping it forfeits
that protection and is not needed for ordinary rollback. Keep the backup for a
full restore if v1 data semantics must also be restored.

`POST /v1/ids` accepts up to 200 reservations per call, capped at 2000 reserved
rows per surface (`429`); a batch exceeding the quota rolls back completely.
Activating an existing reservation frees quota. Reservations never expire.
Only the registry creates IDs; the Python module intentionally has no local ID
generator. Upsert without `id` allocates online; a supplied unknown ID returns
`409 not_allocated`. Activate a reservation on the same surface that reserved it.

```sh
artifact pool refill --surface notify
artifact pool take --surface notify     # works without a network or client token
artifact link card:18557 explains explainer:slug
artifact resolve card:18557 --depth 2
```

Pools are locked across processes, atomically replaced and mode 0600. Each pool
is a JSON array in `~/.config/artifact-ids/pool-<surface>.json` (surface names are
percent-escaped for safe filenames). Refill below 50 replenishes to 200. A failed
network refill leaves the pool intact; unused registry reservations remain valid.
A taken ID is removed durably before it is returned; a crash can waste an ID but
cannot return it twice. Pool reservations are surface-specific.

Aliases are lowercase and permanent: omission or `aliases: []` leaves earlier
bindings intact; reassignment returns `409 alias_taken`. Canonical six-hex IDs
win over aliases, including six-digit numbers. `Karte 18557`, `card 18557`, and
other bare numbers map to `card:18557`. Namespaced aliases such as `board:42` and
`explainer:slug` work directly. Encoded `a%23abcdef` is accepted. URL callers
should use bare hex IDs; never put an unescaped `#` in a URL.

Upsert and sync accept `links: [{"rel":"explains","to":"explainer:slug"}]`.
Targets may be IDs or aliases, including aliases declared later in a manifest.
Links accumulate idempotently. `explains`/`explained_by` and
`supersedes`/`superseded_by` have named inverses; `related` is symmetric.
The closed relation vocabulary has no directional inverses for `discussed_in`,
`decided_by`, `depends_on` or `shows_data_of`, so their reverse discovery edge is
`related`. Links retain creator, timestamp and optional guarded note.
`superseded_by` is also an artifact field; set it explicitly when retiring a row.

Resolve always includes `links`. With `depth=1|2` it includes `linked_nodes`, a
cycle-safe breadth-first traversal of at most 12 unique linked nodes per root,
with id/title/summary/kind/status. HTTP defaults to depth 0 for compatibility;
CLI/MCP default to 1 for voice context. Maximum depth is 2. Reserved rows are
excluded from reads/traversal. Device tokens may read any other access level;
public renderers must filter `access=public` themselves.

Sync example (items may also be an object keyed by component key):

```json
{
  "surface": "app:example",
  "sync_source": "components.json",
  "generation": "1793404800:abcdef1234567",
  "sha": "abcdef1234567",
  "items": [{"id":"abcdef","kind":"panel","title":"Overview","refs":[]}]
}
```

Each sync requires a strictly increasing generation: a nonnegative integer commit
timestamp or `timestamp:sha`, no more than one day in the future. Compare timestamps
numerically, then SHA text for
equal timestamps. Replays and older generations return `409 stale_generation`.
All items are validated before writes and committed with state/retirement/audit in
one transaction. Retirement applies only to `(surface, sync_source)`. Empty
manifests or manifests smaller than half the active source set require
`allow_shrink: true` (`409 shrink_refused` otherwise). Returning IDs reactivate;
retired rows remain resolvable, with `superseded_by` if supplied. A different sync
source cannot take over an existing source's row.

Manifest refs replace only `origin=manifest`; omitted `refs` means an empty
manifest ref set. Agent and timer refs survive. Ordinary upserts force agent
origin, including attempts to claim manifest origin. Explicit `origin=timer`
requires the additional `timer` scope. Ref identity remains `(artifact_id,kind,target)`:
a duplicate target already owned by another origin is preserved without takeover.
`last_synced` and `deployed_rev` are recorded at sync. Every row with
`access != public` rejects email addresses and currency/coin
amounts containing three or more digits in titles, summaries and ref labels. All
access levels reject possible secrets, IBANs and seed phrases. URLs, selectors,
ref targets and link notes reject credentials and URL userinfo. Artifacts with
aliases cannot be deleted: their foreign key uses RESTRICT.

`artifact sync manifest.json` preserves both `items` arrays and component-keyed
`items` objects. If generation is absent, the CLI uses the manifest repository's
`git log -1 --format=%ct:%H` (commit timestamp plus SHA), falling back to current
Unix time outside a usable checkout. `--generation TIMESTAMP[:SHA]` overrides
both the file and automatic value; an explicit generation in the file is retained
otherwise. Repeated syncs of an unchanged commit correctly return 409.

### Reference verification timer (documentation only)

`artifact verify-refs --repo owner/project=/path/to/checkout` checks each active
code ref at its pinned SHA and at HEAD. Repeat `--repo` for multiple checkouts;
unmapped GitHub repos use `gh api` with the caller's existing login. Missing or
unavailable paths fail conservatively as stale. It never fetches code to disk.
The authenticated read/write `/v1/verify-refs` helper pages through all active
code refs and updates `refs_verified_at` / `stale_reason` only if the exact ref
snapshot is unchanged. A concurrent ref edit returns `409 refs_changed`; the CLI
counts that row in `conflicts` and continues with the remaining rows. Retry on the
next pass for skipped rows; other HTTP errors still fail the command. Verification
results never update manifest timestamps.

An operator can install these units after review; this change installs nothing:

```ini
# artifact-verify-refs.service
[Unit]
Description=Verify artifact code references
[Service]
Type=oneshot
ExecStart=/home/flori/bin/artifact verify-refs
TimeoutStartSec=30min

# artifact-verify-refs.timer
[Unit]
Description=Daily artifact reference verification
[Timer]
OnCalendar=daily
RandomizedDelaySec=15min
Persistent=true
[Install]
WantedBy=timers.target
```

The service reads credentials using the existing CLI config parser. Put no token
values in unit files. Run `.venv/bin/python -m unittest`; integration tests create
and drop only `artifacts_v2test`, refusing to run if it already exists. They first
upgrade a populated copy of the v1 schema, then verify both old routes and v2
semantics. OCR vectors in `testdata/ocr-ids.json` are shared consumer fixtures;
exact candidates sort before OCR substitutions, results are deduplicated and
capped at 20, and callers must confirm candidates with `/v1/exists`.

### Shared badges and central manifest sync

Include `/static/artifact-badge.css` and deferred `/static/artifact-badge.js` from the
registry origin, then render `<span class="aid" data-aid="b8c3ff">a#b8c3ff</span>`
inside a positioned container. These two exact GET routes are anonymous; API routes
retain bearer authentication. Assets cache for one hour. The badge supports click
and Enter/Space copying, a short success toast, and dynamically inserted elements.
Allow the asset origin in CSP `script-src`/`style-src`; inline permissions are not needed.

`bin/artifact-sync-all` reads `~/.config/artifact-sync/sources.json` (example in
`deploy/sources.example.json`). Each entry names `repo`, `path`, `branch`; a normal
manifest contains `surface` and `items`. Legacy keyed objects need a source `surface`;
`alias_prefix` adds `<prefix><key>` aliases. Source `url`, `owner_job`, `access` are
optional item defaults. The runner resolves branch HEAD once, fetches its immutable
manifest through `gh api`, and sends the CLI's shared sync payload with generation
`<commit unix time>:<sha>` and source `github:<repo>/<path>`. Only a 409
`stale_generation` counts as no change; other errors cause a nonzero exit after
remaining sources run. One JSON line per source is appended to
`~/.local/state/artifact-sync/log`; payloads and credentials are never logged.

To install locally, symlink `bin/artifact-sync-all` into `~/bin`, copy the four unit
files in `deploy/` into `~/.config/systemd/user/`, run `systemctl --user daemon-reload`,
then `systemctl --user enable --now artifact-sync-all.timer artifact-verify-refs.timer`.
The sync timer runs every 15 minutes; reference verification runs daily. Units load
the existing private `dev-secrets.env` and optional `extra-secrets.env`; they contain
no credential values. Review the unit paths and credential loading for another host.
The installed sync symlink must point to a persistent checkout; after merging, move
it to the main checkout. Skill source for installation is in
`deploy/agent-artifact-ids.SKILL.md`.


## Device credentials (migration 003)

Apply `migrations/003_devices.sql` to the registry database after 001/002, before deploying
Desk's registry-backed device service. It is idempotent and grants the `devices` API scope to
the existing token named `desk`; no other token gains access. API token caches expire after
60 seconds (restart the registry to apply the grant immediately). No plaintext device tokens
are stored or returned; callers provide HMAC-SHA256 hashes.

- `POST /v1/devices`: `{hash,label,scopes,expires_at}` -> `{id}`. hash is 64 lowercase hex,
  scopes is a nonempty subset of dictate/dictionary/screen/exists; expires_at is Unix milliseconds
  in the next 90 days. At most 1000 active devices. IDs are UUIDs.
- `POST /v1/devices/verify`: `{hash}` -> `{id,scopes,expires_at}`; expires_at is ISO 8601 UTC.
  Revoked/expired/unknown hashes return 404. last_seen writes occur at most once per minute.
- `GET /v1/devices`: `{devices:[{id,label,scopes,created_at,expires_at,revoked_at,last_seen}]}`
  lists active devices with ISO timestamps. Hashes never appear in lists.
- `DELETE /v1/devices/:id`: empty body or `{}` -> `{ok:true}`; sets revoked_at idempotently.
- `DELETE /v1/dictionary/:term`: scope dict, URL-encoded term, empty body or `{}` -> `{ok:true}`.
  Only source=learned rows can be deleted; manual/harvest/wispr/unknown return 404.
  A learned upsert does not convert an existing non-learned row into a deletable learned row.

The integration test applies migration 003 twice in its owned throwaway database and checks
device scope, create/list/verify, last_seen throttling, expiry/revoke and learned-only deletion.
