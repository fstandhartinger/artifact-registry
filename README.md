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
table stores only SHA256 hashes with `read`, `write`, and/or `dict` scopes.
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
Parents can appear after children in a manifest. App/panel/element/card and finance summaries/titles reject
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
`artifacts_test`, refusing to touch an already-existing test database. Production
registry data is not modified. CLI module tests alone:

```sh
python -m unittest tests.test_ids
```

MCP uses newline-delimited JSON-RPC over stdio, protocol `2025-06-18`, and exports
`artifact_resolve`, `artifact_search`, `artifact_list`, and `artifact_upsert`.
Only protocol messages are written to stdout.

Pinned GitHub SHA existence is checked through the public GitHub commit API with a
shared two-second budget per request and a bounded 15-minute cache. Missing or
unverifiable commits (including private repos without public API access) are marked
stale conservatively. Network failures are cached for one minute. Manifest age over
seven days also marks an artifact stale.

Limitations: no pagination beyond the bounded list/search limit (200), CORS, or browser token
handling is provided; use an authenticated server-side gateway. Dictionary reads return
the full dictionary. Reservations and write tokens are trusted internal capabilities,
not per-surface permissions. `stamp` writes a sibling `.stamped.png`, preserving the
input image. Docker deployment must copy the `data` directory for the recovery-phrase
filter. BIP39 word list attribution is in `data/README.md`.

## Registry v2

Apply `migrations/002_v2.sql` **after** `001_init.sql`, as the database owner, in
one transaction (`psql --single-transaction -v ON_ERROR_STOP=1 -f ...`). It adds
columns/tables, an alias index and an immutability trigger; it neither deletes nor
rewrites artifact/ref rows. Existing v1 artifacts count as allocated. Existing
refs acquire `origin=agent`, conservatively preserving them at manifest sync.
If pre-existing aliases differ only by case, the new unique index refuses the
migration; review those bindings before retrying. Do not reassign an alias to
resolve this conflict. Existing mixed-case aliases remain readable case-insensitively.

`POST /v1/ids` accepts up to 200 reservations per call. Reservations never expire.
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
timestamp or `timestamp:sha`. Compare timestamps numerically, then SHA text for
equal timestamps. Replays and older generations return `409 stale_generation`.
All items are validated before writes and committed with state/retirement/audit in
one transaction. Retirement applies only to `(surface, sync_source)`. Empty
manifests or manifests smaller than half the active source set require
`allow_shrink: true` (`409 shrink_refused` otherwise). Returning IDs reactivate;
retired rows remain resolvable, with `superseded_by` if supplied. A different sync
source cannot take over an existing source's row.

Manifest refs replace only `origin=manifest`; omitted `refs` means an empty
manifest ref set. Agent and timer refs survive. Upsert refs default to agent;
explicit `origin=timer` is supported. Ref identity remains `(artifact_id,kind,target)`:
a duplicate target already owned by another origin is preserved without takeover.
`last_synced` and `deployed_rev` are recorded at sync. The `app:*` surfaces and
panel/element/card kinds reject email addresses, IBANs, possible secrets and
currency/coin amounts containing three or more digits in title/summary.

### Reference verification timer (documentation only)

`artifact verify-refs --repo owner/project=/path/to/checkout` checks each active
code ref at its pinned SHA and at HEAD. Repeat `--repo` for multiple checkouts;
unmapped GitHub repos use `gh api` with the caller's existing login. Missing or
unavailable paths fail conservatively as stale. It never fetches code to disk.
The authenticated read/write `/v1/verify-refs` helper pages through all active
code refs and updates `refs_verified_at` / `stale_reason` only if the exact ref
snapshot is unchanged. A concurrent ref edit returns `409 refs_changed`; retry
the command. Verification results never update manifest timestamps.

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
