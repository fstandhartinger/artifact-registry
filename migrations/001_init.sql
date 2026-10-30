CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE TABLE IF NOT EXISTS artifact (
 id text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{6}$'),
 kind text NOT NULL, title text NOT NULL CHECK(length(title)<=200),
 summary text NOT NULL DEFAULT '' CHECK(length(summary)<=1200), surface text NOT NULL,
 owner_job text, parent text REFERENCES artifact(id), url text, selector text,
 access text NOT NULL DEFAULT 'private' CHECK(access IN ('private','internal','public')),
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('reserved','active','retired')),
 sync_source text, last_verified timestamptz, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now(),
 search tsvector GENERATED ALWAYS AS (to_tsvector('simple',title||' '||summary)) STORED
);
CREATE INDEX IF NOT EXISTS artifact_search_idx ON artifact USING gin(search);
CREATE INDEX IF NOT EXISTS artifact_title_trgm_idx ON artifact USING gin(title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS artifact_surface_idx ON artifact(surface);
CREATE TABLE IF NOT EXISTS artifact_ref (
 artifact_id text REFERENCES artifact(id) ON DELETE CASCADE, kind text NOT NULL, target text NOT NULL,
 label text, pinned_sha text, ord int DEFAULT 0, PRIMARY KEY(artifact_id,kind,target)
);
CREATE TABLE IF NOT EXISTS artifact_alias(alias text PRIMARY KEY,artifact_id text REFERENCES artifact(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS dictionary (
 term text PRIMARY KEY, replace_from text[] DEFAULT '{}', source text, weight int DEFAULT 1,
 created_at timestamptz DEFAULT now(), last_used timestamptz, note text
);
CREATE TABLE IF NOT EXISTS audit(ts timestamptz DEFAULT now(),actor text,action text,artifact_id text,detail jsonb);
CREATE TABLE IF NOT EXISTS token(name text PRIMARY KEY,hash text NOT NULL,scopes text[] NOT NULL,created_at timestamptz DEFAULT now());
