-- Session trace store. Additive and repeatable; apply after 001-003 as the database owner.
BEGIN;
CREATE TABLE IF NOT EXISTS session_meta (
 session_id text PRIMARY KEY REFERENCES artifact(id), kind text NOT NULL CHECK (kind IN ('voice','chat')),
 provider text NOT NULL, model text, slug text, device text, client jsonb NOT NULL DEFAULT '{}', entry jsonb NOT NULL DEFAULT '{}',
 gateway_commit text, started_at timestamptz NOT NULL DEFAULT now(), ended_at timestamptz,
 flagged boolean NOT NULL DEFAULT false, flag_reason text, flag_sent_at timestamptz
);
CREATE INDEX IF NOT EXISTS session_meta_slug_idx ON session_meta(slug);
CREATE INDEX IF NOT EXISTS session_meta_started_idx ON session_meta(started_at DESC);
CREATE TABLE IF NOT EXISTS session_trace (
 session_id text NOT NULL REFERENCES artifact(id), seq bigint NOT NULL CHECK (seq >= 0), ts timestamptz NOT NULL,
 source text NOT NULL, turn int, type text NOT NULL, data jsonb NOT NULL DEFAULT '{}',
 PRIMARY KEY (session_id, source, seq)
);
CREATE INDEX IF NOT EXISTS session_trace_ts_idx ON session_trace(ts);
-- Append only: UPDATE is always refused; DELETE only inside session_trace_retention().
CREATE OR REPLACE FUNCTION session_trace_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'DELETE' AND current_setting('session_trace.retention', true) = 'on' THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'session_trace is append only';
END $$;
DROP TRIGGER IF EXISTS session_trace_guard ON session_trace;
CREATE TRIGGER session_trace_guard BEFORE UPDATE OR DELETE ON session_trace
 FOR EACH ROW EXECUTE FUNCTION session_trace_guard();
-- Deletes trace rows older than the cutoff; artifact rows stay, retired once their trace is gone.
CREATE OR REPLACE FUNCTION session_trace_retention(keep_days int DEFAULT 30) RETURNS int LANGUAGE plpgsql AS $$
DECLARE removed int;
BEGIN
 PERFORM set_config('session_trace.retention', 'on', true);
 DELETE FROM session_trace WHERE ts < now() - make_interval(days => keep_days);
 GET DIAGNOSTICS removed = ROW_COUNT;
 PERFORM set_config('session_trace.retention', 'off', true);
 UPDATE artifact a SET status = 'retired', updated_at = now()
  FROM session_meta m WHERE m.session_id = a.id AND a.kind = 'session' AND a.status = 'active'
   AND m.started_at < now() - make_interval(days => keep_days)
   AND NOT EXISTS (SELECT 1 FROM session_trace t WHERE t.session_id = a.id);
 RETURN removed;
END $$;
UPDATE token SET scopes = array_append(scopes, 'trace') WHERE name = 'desk' AND NOT ('trace' = ANY(scopes));
COMMIT;
