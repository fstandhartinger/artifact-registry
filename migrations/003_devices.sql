BEGIN;
CREATE TABLE IF NOT EXISTS device (
 id uuid PRIMARY KEY,
 hash text UNIQUE NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
 label text NOT NULL CHECK (length(label) <= 100),
 scopes text[] NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 last_seen timestamptz
);
UPDATE token SET scopes=array_append(scopes,'devices')
 WHERE name='desk' AND NOT ('devices'=ANY(scopes));
COMMIT;
