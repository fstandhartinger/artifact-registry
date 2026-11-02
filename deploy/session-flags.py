#!/usr/bin/env python3
"""Hourly: post one board digest line per newly flagged session (no Telegram), then mark it sent.
Goes through the registry API with the agent token (scopes read + sync), never the database;
NOTIFY overrides the notify path."""
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from artifact_cli import Client  # noqa: E402

def main(client=None):
    client = client or Client()
    rows = client.request('/v1/sessions/flags')['items']
    notify = os.environ.get('NOTIFY', os.path.expanduser('~/bin/notify'))
    failed = 0
    for row in rows:
        if not re.fullmatch(r'a#[0-9a-f]{6}', row['id']): continue
        line = f"{row['id']} unbeantwortet/auffaellig: {row['reason'] or 'Sitzung markiert'} – desk-trace {row['id']}"
        done = subprocess.run([notify, 'digest', 'desk-trace', line], capture_output=True, text=True, timeout=60)
        if done.returncode: failed += 1; print(f"notify failed for {row['id']}: exit {done.returncode}", file=sys.stderr); continue
        client.request('/v1/sessions/flags/sent', {'ids': [row['id']]})
        print(f"digest {row['id']}")
    return 1 if failed else 0

if __name__ == '__main__': raise SystemExit(main())
