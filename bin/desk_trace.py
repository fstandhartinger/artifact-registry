"""Read a Desk session trace from the artifact registry: meta, diagnosis, compact timeline."""
import argparse
import json
import sys
from datetime import datetime
from artifact_cli import Client

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

def main(argv=None):
    parser = argparse.ArgumentParser(prog='desk-trace', description='Read a Desk session trace')
    parser.add_argument('session', help='a#id, 6-hex id, slug or "last"')
    parser.add_argument('--json', action='store_true'); parser.add_argument('--raw', action='store_true'); parser.add_argument('--diagnosis-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        client = Client()
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
