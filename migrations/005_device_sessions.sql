-- Session kind 'device': a per-day trace for device events outside a voice/chat session. Additive and repeatable; apply after 004 as the database owner.
BEGIN;
ALTER TABLE session_meta DROP CONSTRAINT IF EXISTS session_meta_kind_check;
ALTER TABLE session_meta ADD CONSTRAINT session_meta_kind_check CHECK (kind IN ('voice','chat','device'));
CREATE INDEX IF NOT EXISTS session_meta_kind_started_idx ON session_meta(kind, started_at DESC);
COMMIT;
