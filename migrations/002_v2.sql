-- Self-contained transaction: a failed preflight leaves v1 unchanged.
BEGIN;
DO $$
DECLARE conflicts text;
BEGIN
 SELECT string_agg(key || ' (' || n || ')', ', ' ORDER BY key) INTO conflicts
 FROM (SELECT lower(alias) AS key, count(*) AS n FROM artifact_alias
       GROUP BY lower(alias) HAVING count(*) > 1) duplicates;
 IF conflicts IS NOT NULL THEN
  RAISE EXCEPTION 'case-variant alias duplicates: %. Review bindings and deduplicate before migration 002; see README.', conflicts;
 END IF;
END $$;
ALTER TABLE token ADD COLUMN IF NOT EXISTS surfaces text[];
UPDATE token SET scopes=array_append(scopes,'sync')
 WHERE name IN ('sync','agent') AND NOT ('sync'=ANY(scopes));
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

-- CASCADE previously let deleting an artifact erase its permanent aliases.
ALTER TABLE artifact_alias DROP CONSTRAINT IF EXISTS artifact_alias_artifact_id_fkey;
ALTER TABLE artifact_alias ADD CONSTRAINT artifact_alias_artifact_id_fkey
 FOREIGN KEY(artifact_id) REFERENCES artifact(id) ON DELETE RESTRICT;
COMMIT;
