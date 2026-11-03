#!/usr/bin/env python3
"""Read a Desk session trace from the artifact registry: meta, diagnosis, compact timeline."""
import argparse
import json
import sys
from datetime import datetime
import os
import re
import shlex
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# This one file is the whole tool: it runs as a symlink or as a plain copy in ~/bin, with no module beside it (ModuleNotFoundError on Sandy, 2 Nov).
class Client:
    def __init__(self):
        values = {}
        path = Path.home()/'.config/dev-secrets.env'
        if path.exists():
            for line in path.read_text().splitlines():
                match = re.match(r'^(?:export\s+)?(ARTIFACTS_[A-Z_]+)=(.*)$', line)
                if match:
                    try:
                        parts = shlex.split(match[2], comments=True)
                        if len(parts) == 1: values[match[1]] = parts[0]
                    except ValueError: pass
        values.update({k: v for k, v in os.environ.items() if k.startswith('ARTIFACTS_')})
        self.url = values.get('ARTIFACTS_URL', 'https://artifacts.app.mintapis.com').rstrip('/')
        self.token = values.get('ARTIFACTS_AGENT_TOKEN', '')
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in {'https', 'http'} or (parsed.scheme == 'http' and parsed.hostname not in {'localhost', '127.0.0.1', '::1'}):
            raise ValueError('registry URL requires HTTPS except on loopback')
    def request(self, path, **query):
        url = self.url+path+('?'+urllib.parse.urlencode(query) if query else '')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs): return None
        req = urllib.request.Request(url, headers={'Authorization': 'Bearer '+self.token, 'Accept': 'application/json'})
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=10) as response: return json.load(response)
        except urllib.error.HTTPError as e:
            try: message = json.load(e).get('error', 'request refused')
            except (ValueError, AttributeError): message = 'request refused'
            raise ValueError(f'registry HTTP {e.code}: {message}') from None
        except (urllib.error.URLError, TimeoutError): raise ValueError('registry unavailable') from None

def say(data):
    if isinstance(data, dict):
        for key in ('text', 'name', 'tool', 'error', 'message', 'code', 'status', 'call_id', 'age_s', 'path'):
            if data.get(key) not in (None, ''): yield f'{key}={json.dumps(data[key], ensure_ascii=False)[:90]}'

def timeline(events):
    if not events: return []
    t0 = datetime.fromisoformat(events[0]['ts'])
    lines = []
    for e in events:
        rel = (datetime.fromisoformat(e['ts'])-t0).total_seconds()
        turn = '' if e['turn'] is None else f" t{e['turn']}"
        lines.append(f"{rel:7.1f}s {e['source'][:8]:<8}{turn:<4} {e['type']:<28} {' '.join(say(e['data']))}".rstrip())
    return lines

def render_diagnosis(d):
    out = ['Was ist passiert:'] + ['  '+line for line in d['what_happened'].splitlines()]
    out.append(f"Flag: {'JA – '+d['flag_reason'] if d['flagged'] else 'nein'}")
    for key, label in (('unanswered', 'Unbeantwortet'), ('silent_gaps', 'Stille >20 s'), ('stale', 'Veraltete Ergebnisse'), ('tool_errors', 'Werkzeugfehler'), ('provider_errors', 'Anbieterfehler'), ('watchdog', 'Watchdog')):
        if d[key]: out.append(f'{label}: '+json.dumps(d[key], ensure_ascii=False))
    out.append(f"Mikro stumm: {d['mute_s']} s; Bilder: {json.dumps(d['frames'])}; Unterbrechungen: {d['barge_ins']}; Kosten USD: {d['cost_usd']}")
    return out

def relay(argv):
    # No token in this shell (LeChonk keeps none): the same read goes through Sandy's read-only relay, so no secret lands here.
    tool = shutil.which('sandy-read') or str(Path.home()/'bin/sandy-read')
    if not os.access(tool, os.X_OK) or os.environ.get('DESK_TRACE_NO_RELAY'): return None
    return subprocess.run([tool, 'desk-trace', *argv]).returncode

def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = argparse.ArgumentParser(prog='desk-trace', description='Read a Desk session trace')
    parser.add_argument('session', help='a#id, 6-hex id, slug or "last"')
    parser.add_argument('--json', action='store_true'); parser.add_argument('--raw', action='store_true'); parser.add_argument('--diagnosis-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        client = Client()
        if not client.token:
            code = relay(argv)
            if code is not None: return code
            print('desk-trace: no ARTIFACTS_AGENT_TOKEN and no sandy-read relay on this host', file=sys.stderr); return 1
        meta = client.request('/v1/sessions/lookup', q=args.session)
        aid = meta['id'].removeprefix('a#')
        diagnosis = client.request(f'/v1/sessions/{aid}/diagnosis')['diagnosis']
        events = [] if args.diagnosis_only else client.request(f'/v1/sessions/{aid}/trace')['events']
    except (ValueError, OSError) as e:
        print(str(e), file=sys.stderr); return 1
    if args.raw:
        for e in events: print(json.dumps(e, ensure_ascii=False))
        return 0
    if args.json:
        print(json.dumps({'session': meta, 'diagnosis': diagnosis, **({} if args.diagnosis_only else {'events': events})}, indent=2, ensure_ascii=False)); return 0
    print(f"{meta['id']}  {meta['title']}  [{meta['kind']}, {meta['provider']}/{meta.get('model') or '?'}, slug={meta.get('slug') or '-'}]")
    print(f"gestartet {meta['started_at']}  beendet {meta.get('ended_at') or '-'}  gateway {meta.get('gateway_commit') or '-'}  client {json.dumps(meta.get('client'), ensure_ascii=False)}  entry {json.dumps(meta.get('entry'), ensure_ascii=False)}")
    print('\n'.join(render_diagnosis(diagnosis)))
    if events: print('\nTimeline:'); print('\n'.join(timeline(events)))
    return 0
if __name__ == '__main__': raise SystemExit(main())
