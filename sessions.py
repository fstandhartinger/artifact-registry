"""Pure helpers for the session trace store: event scrubbing and diagnosis. No database access."""
import re
from datetime import datetime, timedelta, timezone

MAX_EVENT_BYTES = 16 * 1024
MAX_BATCH = 500
SILENCE_S = 20
BLOB_NAMES = {'image','images','audio','pcm','png','jpeg','jpg'}

def blob_field(key, item):
    key = key.lower()
    return key in BLOB_NAMES or (any(t in BLOB_NAMES for t in re.split(r'[_\-.]', key)) and (isinstance(item, (dict, list)) or (isinstance(item, str) and len(item) > 64)))
BLOB_VALUE = re.compile(r'[A-Za-z0-9+/_=-]{1024,}')
PROGRESS = {'transcript.assistant.final','transcript.assistant.delta','tool.done','tool.result_sent'}
MONTHS = ['Jan','Feb','Mär','Apr','Mai','Jun','Jul','Aug','Sep','Okt','Nov','Dez']

def clamp_ts(ts, now, back=timedelta(days=1), ahead=timedelta(minutes=5)):
    """A foreign clock must not decide retention."""
    return now if ts > now+ahead or ts < now-back else ts

def parse_ts(value):
    if isinstance(value, bool): raise ValueError('bad ts')
    if isinstance(value, (int, float)):
        if value < 0 or value > 1e14: raise ValueError('bad ts')
        return datetime.fromtimestamp(value/1000 if value > 1e11 else value, timezone.utc)
    if isinstance(value, str) and len(value) <= 40:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise ValueError('bad ts')

def scrub(value, secret, depth=0):
    """Redact secrets in every string; drop image/audio fields and base64 blobs. Returns (value, dropped)."""
    if isinstance(value, str):
        return secret.sub('[REDACTED]', value), False
    if depth > 12: return None, True
    if isinstance(value, list):
        out = []; dropped = False
        for item in value:
            item, d = scrub(item, secret, depth+1); out.append(item); dropped |= d
        return out, dropped
    if isinstance(value, dict):
        out = {}; dropped = False
        for key, item in value.items():
            key = secret.sub('[REDACTED]', str(key))[:100]
            if blob_field(key, item) or (isinstance(item, str) and BLOB_VALUE.search(item)):
                dropped = True; continue
            out[key], d = scrub(item, secret, depth+1); dropped |= d
        return out, dropped
    return value, False

def title_for(kind, provider, when):
    return f"{'Voice' if kind == 'voice' else 'Chat'}-Sitzung {when.day} {MONTHS[when.month-1]} {when:%H:%M} ({provider})"

def _text(event):
    value = event['data'].get('text') or event['data'].get('transcript')
    return value.strip() if isinstance(value, str) else ''

def _num(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None

def _dur(seconds):
    seconds = int(round(seconds))
    return f'{seconds//60} min {seconds%60} s' if seconds >= 60 else f'{seconds} s'

def diagnose(meta, events):
    ev = sorted(events, key=lambda e: (e['ts'], e['seq']))
    out = {'session': meta.get('id'), 'events': len(ev), 'turns': [], 'unanswered': [], 'silent_gaps': [], 'stale': [], 'tool_errors': [],
           'provider_errors': [], 'watchdog': [], 'barge_ins': 0, 'mute_s': 0.0, 'frames': {}, 'cost_usd': None, 'duration_s': 0.0,
           'ended': bool(meta.get('ended_at')), 'flagged': False, 'flag_reason': None, 'what_happened': 'Keine Ereignisse aufgezeichnet.'}
    if not ev: return out
    t0 = ev[0]['ts']; rel = lambda ts: round((ts-t0).total_seconds(), 1)
    stop = next((e for e in reversed(ev) if e['type'] == 'session.stop'), None)
    end = stop['ts'] if stop else ev[-1]['ts']
    out['ended'] = out['ended'] or stop is not None
    out['duration_s'] = rel(end)
    turns = []; calls = {}; muted_at = None; markers = set(); no_answer_at = []; cost_sum = 0.0; cost_seen = False; stop_cost = None
    for e in ev:
        t, d = e['type'], e['data']
        if t in ('turn.user.start', 'transcript.user.final'):
            n = e['turn']
            cur = next((x for x in reversed(turns) if n is not None and x['turn'] == n), None)
            if cur is None and t == 'transcript.user.final' and turns and turns[-1]['question'] is None and turns[-1]['answer_at'] is None and turns[-1]['turn'] in (None, n):
                cur = turns[-1]
            if cur is None:
                cur = {'turn': n, 'at': e['ts'], 'question': None, 'answer_at': None}; turns.append(cur)
            if t == 'transcript.user.final' and _text(e): cur['question'] = _text(e)
            if d.get('marker') or (cur['question'] or '').startswith('[Markierung]'): cur['marker'] = True
        elif t == 'transcript.assistant.final' and _text(e) and turns:
            cur = next((x for x in reversed(turns) if e['turn'] is not None and x['turn'] == e['turn']), turns[-1])
            if cur['answer_at'] is None: cur['answer_at'] = e['ts']
        elif t == 'tool.call': calls[str(d.get('call_id') or d.get('id'))] = d.get('name') or d.get('tool')
        elif t == 'tool.stale':
            cid = str(d.get('call_id') or d.get('id'))
            out['stale'].append({'at_s': rel(e['ts']), 'tool': d.get('name') or d.get('tool') or calls.get(cid), 'call_id': cid, 'age_s': _num(d.get('age_s'))})
        elif t == 'tool.error':
            cid = str(d.get('call_id') or d.get('id'))
            out['tool_errors'].append({'at_s': rel(e['ts']), 'tool': d.get('name') or d.get('tool') or calls.get(cid), 'error': str(d.get('error') or d.get('message') or '')[:200]})
        elif t == 'provider.error': out['provider_errors'].append({'at_s': rel(e['ts']), 'error': str(d.get('error') or d.get('message') or d.get('code') or '')[:200]})
        elif t.startswith('watchdog.'):
            out['watchdog'].append({'at_s': rel(e['ts']), 'type': t})
            if t == 'watchdog.no_answer': no_answer_at.append(e['ts'])
        elif t == 'turn.unanswered': markers.add(e['turn'])
        elif t == 'barge_in': out['barge_ins'] += 1
        elif t == 'mic.mute' and muted_at is None: muted_at = e['ts']
        elif t == 'mic.unmute' and muted_at is not None:
            out['mute_s'] += (e['ts']-muted_at).total_seconds(); muted_at = None
        elif t.startswith('screen.frame'):
            state = t.split('.', 2)[2] if t.count('.') >= 2 else str(d.get('decision') or d.get('status') or d.get('result') or d.get('state') or ('sent' if d.get('reason') else 'other'))
            state = {'dedup': 'deduped', 'duplicate': 'deduped', 'skip': 'skipped'}.get(state, state)
            out['frames'][state] = out['frames'].get(state, 0)+1
        c = _num(d.get('cost_usd', d.get('costUsd', d.get('cost'))))
        if c is not None:
            if t == 'session.stop': stop_cost = c
            elif t == 'response.done': cost_sum += c; cost_seen = True
    if muted_at is not None: out['mute_s'] += (end-muted_at).total_seconds()
    out['mute_s'] = round(out['mute_s'], 1)
    out['cost_usd'] = stop_cost if stop_cost is not None else (round(cost_sum, 4) if cost_seen else None)
    ended = out['ended']
    # One sentence the vendor delivered in growing fragments is one question, and a drawn marking is context, not a question (a#7f54a5).
    # Since gateway v0.1.5 a grown fragment keeps its turn id, so the last transcript is the question; older traces gave every fragment a new turn.
    same = lambda a, b: ' '.join(b.split()).startswith(' '.join(a.rstrip(' .,?!').split()))
    out['markings'] = sum(1 for x in turns if x.get('marker'))
    # A marking the agent did answer is no question; one it did not answer stays a finding, that was the bug in a#7f54a5.
    turns = [x for i, x in enumerate(turns) if not (x.get('marker') and x['answer_at'] is not None) and not (
        x['answer_at'] is None and not x.get('marker') and x['question'] and i+1 < len(turns) and turns[i+1]['question'] and same(x['question'], turns[i+1]['question']))]
    for i, x in enumerate(turns):
        last = i == len(turns)-1
        window_end = x['answer_at'] or (end if last else turns[i+1]['at'])
        answered = x['answer_at'] is not None
        row = {'turn': x['turn'], 'at_s': rel(x['at']), 'question': x['question'], 'answered': answered, 'answer_at_s': rel(x['answer_at']) if answered else None}
        out['turns'].append(row)
        if not answered and (ended or not last or x['turn'] in markers or any(a >= x['at'] for a in no_answer_at)):
            out['unanswered'].append(row)
        points = [x['at']]+[e['ts'] for e in ev if e['type'] in PROGRESS and x['at'] < e['ts'] < window_end]+[window_end]
        for a, b in zip(points, points[1:]):
            if (b-a).total_seconds() > SILENCE_S:
                out['silent_gaps'].append({'turn': x['turn'], 'from_s': rel(a), 'to_s': rel(b), 'seconds': round((b-a).total_seconds(), 1), 'question_waiting': True, 'answered': answered})
    reasons = []
    if out['unanswered']:
        reasons.append(f"{len(out['unanswered'])} Frage(n) ohne Antwort")  # no question text: this line goes to the board digest and outlives the trace
    if out['unanswered'] and out['stale']: reasons.append('Ergebnis veraltet' + (f" ({out['stale'][0]['tool']})" if out['stale'][0]['tool'] else ''))
    if out['unanswered'] and out['silent_gaps']: reasons.append(f"Stille {int(max(g['seconds'] for g in out['silent_gaps']))} s")
    out['flagged'] = bool(out['unanswered']); out['flag_reason'] = '; '.join(reasons)[:300] if reasons else None
    lines = [f"Sitzung ({meta.get('kind') or 'voice'}, {meta.get('provider') or '?'}) dauerte {_dur(out['duration_s'])}" + (f", Kosten USD {out['cost_usd']:.2f}." if out['cost_usd'] is not None else '.')]
    lines.append(f"{len(out['turns'])} Frage(n), {len(out['unanswered'])} ohne Antwort" + (f": „{(out['unanswered'][0]['question'] or 'ohne Transkript')[:80]}“ (bei {out['unanswered'][0]['at_s']} s)." if out['unanswered'] else '.'))
    if out['stale']:
        s = out['stale'][0]
        lines.append(f"Ergebnis von {s['tool'] or 'einem Werkzeug'} kam veraltet an (stale)" + (f" nach {s['age_s']:g} s" if s['age_s'] is not None else '') + (f"; insgesamt {len(out['stale'])}×." if len(out['stale']) > 1 else '.'))
    if out['silent_gaps']:
        g = max(out['silent_gaps'], key=lambda g: g['seconds'])
        lines.append(f"Stille: längste Lücke {int(g['seconds'])} s ohne Antwort ({g['from_s']:g}–{g['to_s']:g} s)" + (f", {out['barge_ins']} Unterbrechung(en) durch Sprechen." if out['barge_ins'] else '.'))
    elif out['barge_ins']: lines.append(f"{out['barge_ins']} Unterbrechung(en) durch Sprechen.")
    extra = []
    if out['watchdog']: extra.append(f"Watchdog {len(out['watchdog'])}×")
    if out['tool_errors']: extra.append(f"Werkzeugfehler {len(out['tool_errors'])}×")
    if out['provider_errors']: extra.append(f"Anbieterfehler {len(out['provider_errors'])}×")
    if out['mute_s']: extra.append(f"Mikro stumm {_dur(out['mute_s'])}")
    if out['frames']: extra.append('Bilder ' + ', '.join(f'{k} {v}' for k, v in sorted(out['frames'].items())))
    if extra: lines.append('; '.join(extra)+'.')
    out['what_happened'] = '\n'.join(lines[:5])
    return out

def summary_for(diag):
    parts = [f"{len(diag['turns'])} Turn(s)"]
    if diag['unanswered']: parts.append(f"{len(diag['unanswered'])} unbeantwortet")
    if diag['silent_gaps']: parts.append(f"Stille bis {int(max(g['seconds'] for g in diag['silent_gaps']))} s")
    if diag['stale']: parts.append('veraltetes Ergebnis')
    if diag['tool_errors'] or diag['provider_errors']: parts.append('Fehler')
    return ('⚑ ' if diag['flagged'] else '')+', '.join(parts)+(', beendet' if diag['ended'] else '')
