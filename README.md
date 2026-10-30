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
- POST `/v1/sync` with `{ "surface": "example", "sync_source": "manifest", "sha": "<commit>", "items": [] }`
- POST `/v1/dictionary` with `{ "term": "Example", "replace_from": [], "source": "manual" }`

IDs in responses have the display prefix `a#`; the database stores the hex part.
Resolve accepts canonical IDs case-insensitively and aliases, including bare legacy
card numbers. Unknown IDs are returned separately. Reserved IDs become visible once
upserted. Empty manifests retire all active records of their surface. Ownership cannot
be transferred by an upsert. Writes, including full manifest retirement, are atomic and
audited; a single transaction lock prevents competing writers from taking ownership.
Reservations older than seven days are lazily removed on allocation if unreferenced.

`kind`, `title`, and `surface` are required for a new artifact. Existing IDs support
partial updates. `refs` and `aliases` replace their respective sets when supplied.
Parents can appear after children in a manifest. Finance summaries/titles reject
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
