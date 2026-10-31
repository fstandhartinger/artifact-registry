-- Additive and repeatable; apply after 001. Existing rows remain allocated.
ALTER TABLE artifact_ref ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'agent'
 CHECK (origin IN ('manifest','agent','timer'));
ALTER TABLE artifact ADD COLUMN IF NOT EXISTS last_synced timestamptz;
ALTER TABLE artifact ADD COLUMN IF NOT EXISTS deployed_rev text;
ALTER TABLE artifact ADD COLUMN IF NOT EXISTS refs_verified_at timestamptz;
ALTER TABLE artifact ADD COLUMN IF NOT EXISTS stale_reason text;
ALTER TABLE artifact ADD COLUMN IF NOT EXISTS superseded_by text REFERENCES artifact(id);
CREATE TABLE IF NOT EXISTS artifact_link (
 src text NOT NULL REFERENCES artifact(id), dst text NOT NULL REFERENCES artifact(id),
 rel text NOT NULL CHECK (rel IN ('related','explains','explained_by','discussed_in','decided_by','supersedes','superseded_by','depends_on','shows_data_of')),
 note text, created_by text, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(src,dst,rel)
);
CREATE INDEX IF NOT EXISTS artifact_link_dst_idx ON artifact_link(dst);
CREATE TABLE IF NOT EXISTS sync_state (
 surface text NOT NULL, sync_source text NOT NULL, generation text NOT NULL,
 sha text, at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(surface,sync_source)
);
-- Alias bindings survive omission/deletion and cannot be reassigned, including in SQL.
CREATE OR REPLACE FUNCTION artifact_alias_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'DELETE' OR NEW.alias IS DISTINCT FROM OLD.alias OR NEW.artifact_id IS DISTINCT FROM OLD.artifact_id THEN
  RAISE EXCEPTION 'alias_taken' USING ERRCODE = '23505';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS artifact_alias_immutable ON artifact_alias;
CREATE TRIGGER artifact_alias_immutable BEFORE UPDATE OR DELETE ON artifact_alias
 FOR EACH ROW EXECUTE FUNCTION artifact_alias_immutable();
-- Existing v1 mixed-case bindings are left intact (no data loss); API lookups are
-- case-insensitive and new bindings canonicalized. This index refuses ambiguity.
CREATE UNIQUE INDEX IF NOT EXISTS artifact_alias_lower_idx ON artifact_alias(lower(alias));
