#!/usr/bin/env python3
"""Hourly: post one board digest line per newly flagged session (no Telegram), then mark it sent.
Needs ARTIFACTS_DATABASE_URL (psql) and ~/bin/notify; NOTIFY overrides the notify path."""
import json
import os
import re
import subprocess
import sys

def psql(sql):
    return subprocess.run(['psql', os.environ['ARTIFACTS_DATABASE_URL'], '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True, text=True, check=True, timeout=60).stdout.strip()

def main():
    rows = json.loads(psql("SELECT coalesce(json_agg(json_build_object('id',session_id,'reason',flag_reason) ORDER BY started_at),'[]') FROM session_meta WHERE flagged AND flag_sent_at IS NULL"))
    notify = os.environ.get('NOTIFY', os.path.expanduser('~/bin/notify'))
    failed = 0
    for row in rows:
        if not re.fullmatch(r'[0-9a-f]{6}', row['id']): continue
        line = f"a#{row['id']} unbeantwortet/auffaellig: {row['reason'] or 'Sitzung markiert'} – desk-trace a#{row['id']}"
        done = subprocess.run([notify, 'digest', 'desk-trace', line], capture_output=True, text=True, timeout=60)
        if done.returncode: failed += 1; print(f"notify failed for a#{row['id']}: exit {done.returncode}", file=sys.stderr); continue
        psql(f"UPDATE session_meta SET flag_sent_at=now() WHERE session_id='{row['id']}' AND flag_sent_at IS NULL")
        print(f"digest a#{row['id']}")
    return 1 if failed else 0

if __name__ == '__main__': raise SystemExit(main())
