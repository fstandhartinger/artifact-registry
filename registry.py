"""Small authenticated artifact pointer registry. No request bodies in logs."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, unquote

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg import sql
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'bin'))
from artifact_ids import normalise
import sessions as S

MAX_BODY = 256 * 1024
MAX_EVENTS_BODY = 4 * 1024 * 1024
BIP39_WORDS = frozenset((Path(__file__).parent/'data/bip39-english.txt').read_text().splitlines())
KINDS = {'app','page','panel','element','card','explainer','scene','diagram','doc','job','tweet','board-entry','finance','session'}
REF_KINDS = {'code','repo','file','board','decision','readme','doc','endpoint','url','job','card','explainer','artifact'}
SECRET = re.compile(r'(?i)(?:\b(?:sk-|(?:ghp|github_pat|gho|art|hf)_|xox[baprs]-)[a-z0-9_-]{8,}|\bAKIA[A-Z0-9]{16}\b|\bbearer\s+\S+|\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:password|passwd|api[_ -]?key|access[_ -]?token|secret[_ -]?key)\s*[:=]\s*\S+|\b(?:seed phrase|recovery phrase|mnemonic)\b)')
# IBAN: uppercase country code + check digits + 11-30 alphanumerics in optional groups of 4, digit-heavy.
IBAN = re.compile(r'\b[A-Z]{2}\d{2}(?:[ \t]?[A-Z0-9]){11,30}\b')

def has_iban(value):
    return any(sum(c.isdigit() for c in m.group(0)) >= 10 for m in IBAN.finditer(value.upper()))
AMOUNT = re.compile(r'(?i)(?:[$€£¥₹₿αΞ]|\b(?:EUR|USD|GBP|CHF|JPY|CNY|CAD|AUD|INR|TAO|BTC|ETH|USDT|USDC|SOL|BNB|REAX)\b)\s*[-+]?\s*[\d., ]*\d|\d[\d., ]*\s*(?:[$€£¥₹₿αΞ]|\b(?:EUR|USD|GBP|CHF|JPY|CNY|CAD|AUD|INR|TAO|BTC|ETH|USDT|USDC|SOL|BNB|REAX)\b)')
RELS = {'related','explains','explained_by','discussed_in','decided_by','supersedes','superseded_by','depends_on','shows_data_of'}
INVERSE = {'explains':'explained_by','explained_by':'explains','supersedes':'superseded_by','superseded_by':'supersedes'}
FIELDS = {'superseded_by','deployed_rev','kind','title','summary','surface','owner_job','parent','url','selector','access','status','sync_source'}

# SHA checks return None (unknown) when existence cannot be confirmed.
# GitHub hides private repos with 404; neither 404 nor rate limits prove absence.
_SHA_CACHE = {}
_SHA_LOCK = threading.Lock()

def sha_missing(ref, deadline):
    if ref['kind'] not in {'code','repo'}:
        return False
    match = re.fullmatch(r'github:([\w.-]+)/([\w.-]+)(?:@([^:]+))?(?::.*)?',ref['target'])
    if not match:
        return None
    owner, repo, rev = match.groups()
    if owner in {'.','..'} or repo in {'.','..'}: return None
    sha = ref.get('pinned_sha') or rev
    if not sha or not re.fullmatch(r'[0-9a-f]{7,64}',sha):
        return False
    key = (owner,repo,sha)
    with _SHA_LOCK:
        cached = _SHA_CACHE.get(key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
    remaining = deadline-time.monotonic()
    if remaining <= 0:
        return None
    missing = None; ttl = 60
    try:
        req = urllib.request.Request('https://api.github.com/repos/'+owner+'/'+repo+'/git/commits/'+sha,
                                     headers={'Accept':'application/vnd.github+json','User-Agent':'artifact-registry',
                                              **({'Authorization':'Bearer '+os.environ['GITHUB_TOKEN']} if os.getenv('GITHUB_TOKEN') else {})})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs): return None
        with urllib.request.build_opener(NoRedirect).open(req, timeout=min(1.5,remaining)) as response:
            missing = False if response.status == 200 else None
            ttl = 900 if missing is False else 60
    except urllib.error.HTTPError as error:
        if error.code == 410: missing = True; ttl = 900
    except (OSError,ValueError):
        pass
    with _SHA_LOCK:
        # Bound process memory; no private content is retained.
        if len(_SHA_CACHE)>=4096: _SHA_CACHE.clear()
        _SHA_CACHE[key] = (time.monotonic()+ttl,missing)
    return missing

class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message

def fail(message, status=422):
    raise APIError(status, message)

def text_field(value, name, limit, empty=True):
    if not isinstance(value, str) or len(value) > limit or ('\x00' in value) or (not empty and not value.strip()):
        fail(f'{name} must be a string of at most {limit} characters' + ('' if empty else ' and not empty'))
    return value

def guard(value, finance=False):
    if finance and re.search(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", value):
        fail("title/summary contains an email; store a reference instead")
    if SECRET.search(value) or has_iban(value):
        fail('title/summary contains a possible secret, credential or IBAN; store a reference instead')
    # Detect embedded standard English mnemonic sequences without rejecting prose by word count.
    run = 0
    for word in re.findall(r'[a-z]+', value.lower()):
        run = run + 1 if word in BIP39_WORDS else 0
        if run >= 12:
            fail('title/summary resembles a seed phrase; store a reference instead')
    if finance and any(len(re.sub(r'\D', '', m.group())) >= 3 for m in AMOUNT.finditer(value)):
        fail('finance title/summary contains a currency amount with three or more digits; store a reference instead')

def id_value(value):
    try:
        return normalise(value)
    except ValueError as e:
        fail(str(e))

def audit(db, actor, action, aid=None, detail=None):
    db.execute('INSERT INTO audit(actor,action,artifact_id,detail) VALUES(%s,%s,%s,%s)', (actor,action,aid,Jsonb(detail or {})))

def require_surface(token, surface):
    # Exact names or trailing '*' prefix patterns only; NULL means all surfaces.
    patterns = token.get('surfaces') if token else None
    if patterns is not None and not any(
        surface.startswith(p[:-1]) if p.endswith('*') else surface == p
        for p in patterns
    ): fail('surface not permitted',403)

def pointer_guard(value):
    guard(value)
    if re.search(r'(?i)[a-z][a-z0-9+.-]*://[^/\s]+@|[?&](?:token|key|secret|password|api_key|access_token)=',value):
        fail('pointer contains a possible credential')

def allocate(db, surface, actor):
    if db.execute("SELECT count(*) AS n FROM artifact WHERE surface=%s AND status='reserved'",(surface,)).fetchone()['n'] >= 2000:
        fail('surface reservation quota exceeded',429)
    for _ in range(5):
        aid = secrets.token_hex(3)
        row = db.execute("INSERT INTO artifact(id,kind,title,surface,status) VALUES(%s,'element','',%s,'reserved') ON CONFLICT DO NOTHING RETURNING id", (aid,surface)).fetchone()
        if row:
            audit(db,actor,'reserve',aid)
            return aid
    fail('id allocation conflict; retry',409)

def upsert(db, item, actor, origin="agent", validate_only=False, token=None):
    if not isinstance(item,dict):
        fail('artifact must be an object')
    if set(item) - FIELDS - {'id','refs','aliases','links'}:
        fail('unknown artifact field')
    aid = id_value(item['id']) if 'id' in item and item['id'] is not None else None
    old = db.execute('SELECT * FROM artifact WHERE id=%s FOR UPDATE', (aid,)).fetchone() if aid else None
    if aid and not old:
        fail('not_allocated',409)
    data = {k:old[k] for k in FIELDS} if old else {'summary':'','access':'private','status':'active'}
    if old and old['status'] == 'reserved':
        data['status'] = 'active'
    data.update({k:v for k,v in item.items() if k in FIELDS})
    for name,limit in [('kind',40),('title',200),('summary',1200),('surface',200)]:
        text_field(data.get(name),name,limit,empty=(name=='summary'))
    if not isinstance(data.get('access'),str) or not isinstance(data.get('status'),str) or data['kind'] not in KINDS or data['access'] not in {'private','internal','public'} or data['status'] not in {'active','retired','reserved'}:
        fail('invalid kind, access or status')
    require_surface(token,data['surface'])
    if old and old['surface'] != data['surface']:
        fail('owner_mismatch',409)
    for name in ('owner_job','url','selector','sync_source','deployed_rev'):
        if data.get(name) is not None:
            text_field(data[name],name,4096)
            pointer_guard(data[name])
    if data.get('parent') is not None:
        data['parent'] = id_value(data['parent'])
        if not db.execute('SELECT 1 FROM artifact WHERE id=%s',(data['parent'],)).fetchone(): fail('parent not allocated',409)
        if aid == data['parent']:
            fail('artifact cannot parent itself')
        if origin!='manifest' and aid and db.execute('WITH RECURSIVE parents AS (SELECT id,parent FROM artifact WHERE id=%s UNION SELECT a.id,a.parent FROM artifact a JOIN parents p ON a.id=p.parent) SELECT 1 FROM parents WHERE id=%s', (data['parent'],aid)).fetchone():
            fail('parent cycle')
    if data.get('superseded_by') is not None:
        data['superseded_by'] = id_value(data['superseded_by'])
        if not db.execute('SELECT 1 FROM artifact WHERE id=%s',(data['superseded_by'],)).fetchone(): fail('superseding artifact not allocated',409)
    finance = data['access'] != 'public'
    guard(data['title'],finance); guard(data['summary'],finance)
    refs = item.get('refs')
    if refs is not None:
        if not isinstance(refs,list) or len(refs)>40:
            fail('refs must be an array with at most 40 entries')
        for ref in refs:
            if not isinstance(ref,dict) or set(ref)-{'kind','target','label','pinned_sha','ord','origin'} or not isinstance(ref.get('kind'),str) or ref.get('kind') not in REF_KINDS:
                fail('invalid reference')
            if not isinstance(ref.get('origin',origin),str) or ref.get('origin',origin) not in {'manifest','agent','timer'}: fail('invalid ref origin')
            if origin=='manifest' and ref.get('origin','manifest')!='manifest': fail('manifest refs require manifest origin')
            if origin != 'manifest':
                if ref.get('origin') == 'timer' and (not token or 'timer' not in token['scopes']):
                    fail('insufficient scope: timer',403)
                ref['origin'] = 'timer' if ref.get('origin') == 'timer' else 'agent'
            text_field(ref.get('target'),'ref target',4096,False)
            pointer_guard(ref['target'])
            if ref['kind'] in {'code','repo'}:
                match=re.match(r'github:([^/]+)/([^@:]+)',ref['target'])
                if match and any(part in {'.','..'} for part in match.groups()): fail('invalid repository')
            for field in ('label','pinned_sha'):
                if ref.get(field) is not None:
                    text_field(ref[field],field,500)
            if ref.get('label') is not None: pointer_guard(ref['label']); guard(ref['label'],finance)
            if ref.get('pinned_sha') and not re.fullmatch(r'[0-9a-f]{7,64}',ref['pinned_sha']):
                fail('invalid pinned_sha')
    aliases = item.get('aliases')
    if aliases is not None:
        if not isinstance(aliases,list) or len(aliases)>100:
            fail('aliases must be an array of at most 100 strings')
        aliases = [text_field(a,'alias',300,False).strip().lower() for a in aliases]
        for alias in aliases:
            text_field(alias,'alias',300,False)
            # Canonical IDs must always mean themselves, not a shadowing alias.
            try:
                normalise(alias)
            except ValueError:
                pass
            else:
                fail('aliases cannot look like canonical ids')
            owner = db.execute('SELECT artifact_id FROM artifact_alias WHERE lower(alias)=%s',(alias,)).fetchone()
            if owner and owner['artifact_id']!=aid:
                fail('alias_taken',409)
    links = validate_links(db,item.get('links'),token)
    if validate_only: return aid
    if not aid:
        aid = allocate(db,data['surface'],actor)
    names = ['id'] + sorted(data)
    vals = [aid] + [data[k] for k in sorted(data)]
    # Serialize competing manifest/upsert owners with the advisory lock in dispatch.
    query = sql.SQL('INSERT INTO artifact ({}) VALUES ({}) ON CONFLICT(id) DO UPDATE SET {},updated_at=now() RETURNING *').format(
        sql.SQL(',').join(map(sql.Identifier,names)),sql.SQL(',').join(sql.Placeholder()*len(names)),
        sql.SQL(',').join(sql.SQL('{}=EXCLUDED.{}').format(sql.Identifier(k),sql.Identifier(k)) for k in sorted(data)))
    db.execute(query,vals)
    if refs is not None:
        origins = {r.get('origin',origin) for r in refs} or {origin}
        for ref_origin in origins:
            db.execute('DELETE FROM artifact_ref WHERE artifact_id=%s AND origin=%s',(aid,ref_origin))
        for n,r in enumerate(refs):
            db.execute('INSERT INTO artifact_ref(artifact_id,kind,target,label,pinned_sha,ord,origin) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(artifact_id,kind,target) DO UPDATE SET label=EXCLUDED.label,pinned_sha=EXCLUDED.pinned_sha,ord=EXCLUDED.ord WHERE artifact_ref.origin=EXCLUDED.origin',(aid,r['kind'],r['target'],r.get('label'),r.get('pinned_sha'),n,r.get('origin',origin)))
    if aliases is not None:
        for alias in dict.fromkeys(aliases):
            db.execute('INSERT INTO artifact_alias(alias,artifact_id) VALUES(%s,%s) ON CONFLICT DO NOTHING',(alias,aid))
    for rel,dst,note in links:
        for src,to,relation in [(aid,dst,rel),(dst,aid,INVERSE.get(rel,'related'))]:
            db.execute('INSERT INTO artifact_link(src,dst,rel,note,created_by) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING',(src,to,relation,note,actor))
    audit(db,actor,'upsert',aid)
    return aid

def lookup(db, value, reserved=False):
    text_field(value,'lookup',300,False)
    try:
        aid = normalise(value)
    except ValueError:
        alias = value.strip().lower()
        match = re.fullmatch(r'(?:karte|card)\s+(\d+)',alias)
        if match: alias = 'card:'+match[1]
        elif alias.isdigit(): alias = 'card:'+alias
        row = db.execute('SELECT artifact_id FROM artifact_alias WHERE lower(alias)=%s',(alias,)).fetchone()
        aid = row['artifact_id'] if row else None
    return db.execute("SELECT * FROM artifact WHERE id=%s AND (status!='reserved' OR %s)",(aid,reserved)).fetchone() if aid else None

FILLERS = frozenset('the a an and or of to in on for with is it der die das den dem des ein eine einen und oder von vom um zu zum zur mit im am ist es äh ähm aeh ehm uh um karte karten card cards bitte mal nur noch auch wo was wie geht'.split())
SEARCH_TOKEN = re.compile(r'a#[0-9a-f]{6}|\d+(?:\.\d+)+|\w+')
CARD_WORDS = re.compile(r'\b(?:karte|card)\s+#?(\d+)\b')

def search_tokens(term):
    """Significant words of a spoken query: fillers dropped, version numbers like 1.3 kept, at most 8."""
    words = [w for w in SEARCH_TOKEN.findall(term.lower()) if not w.startswith('a#')]
    kept = [w for w in dict.fromkeys(words) if w not in FILLERS and (len(w) > 1 or w.isdigit())]
    return (kept or list(dict.fromkeys(words)))[:8]

def search_aliases(term):
    low = term.strip().lower()
    out = [low]+['card:'+n for n in CARD_WORDS.findall(low)]+SEARCH_TOKEN.findall(low)
    out += [w for w in re.findall(r'\w+', low) if w.isdigit() and len(w) > 2]
    return list(dict.fromkeys(v for v in out if v))[:12]

def search(db, term, narrow, limit, deadline):
    """Tolerant ranked search: a row matches on ANY significant word; more words first, title before summary, exact before fuzzy, recency last.
    A card number, alias or a#id anywhere in the query returns that row first. Uses the existing GIN indexes (search, title trigram); the summary is only scored on candidates."""
    found = []; seen = set()
    for candidate in search_aliases(term):
        try: row = lookup(db, candidate)
        except APIError: continue
        if row and row['id'] not in seen and row['status'] == 'active' and all(row[k] == v for k, v in narrow.items()):
            found.append(dict(row, _score=100.0, _match='alias')); seen.add(row['id'])
    found = found[:limit]
    tokens = search_tokens(term)
    if tokens and len(found) < limit:
        params = {f't{i}': t for i, t in enumerate(tokens)} | {f'n_{k}': v for k, v in narrow.items()}
        where = ["status='active'"]+[f'{k}=%(n_{k})s' for k in narrow]
        idx = range(len(tokens))
        q = lambda i: f"plainto_tsquery('simple',%(t{i})s::text)"
        fuzzy = lambda i: len(tokens[i]) >= 3  # shorter words are only matched exactly
        cand = ' OR '.join(f"search @@ {q(i)}"+(f" OR %(t{i})s::text <%% title" if fuzzy(i) else '') for i in idx)
        # at most the 500 newest candidates are scored, so a query of only common words stays bounded
        # every per-word fact is computed once per candidate row, then summed
        facts = ','.join(f"to_tsvector('simple',title) @@ {q(i)} AS te{i},search @@ {q(i)} AS se{i},"+(f"word_similarity(%(t{i})s::text,title) AS wt{i},word_similarity(%(t{i})s::text,summary) AS ws{i}" if fuzzy(i) else f"0::real AS wt{i},0::real AS ws{i}") for i in idx)
        matched = '+'.join(f"(te{i} OR se{i} OR wt{i}>=0.5 OR ws{i}>=0.5)::int" for i in idx)
        exact = '+'.join(f"(te{i} OR se{i})::int" for i in idx)
        titled = '+'.join(f"(te{i} OR wt{i}>=0.5)::int" for i in idx)
        score = '+'.join(f"CASE WHEN te{i} THEN 4 WHEN wt{i}>=0.5 THEN 2+wt{i} WHEN se{i} THEN 2 WHEN ws{i}>=0.5 THEN 1+ws{i} ELSE 0 END" for i in idx)
        db.execute("SELECT set_config('pg_trgm.word_similarity_threshold','0.5',true)")
        sql = f"WITH c AS (SELECT a.*,{facts} FROM (SELECT * FROM artifact WHERE {' AND '.join(where)} AND ({cand}) AND NOT (id=ANY(%(seen)s)) ORDER BY updated_at DESC LIMIT 500) a) SELECT c.*,({matched}) AS _matched,({exact}) AS _exact,({titled}) AS _titled,({score}) AS _score FROM c ORDER BY _matched DESC,_titled DESC,_score DESC,updated_at DESC,id LIMIT %(limit)s"
        for r in db.execute(sql, params | {'seen': list(seen), 'limit': limit-len(found)}).fetchall():
            found.append(dict(r, _match='exact' if r['_exact'] == r['_matched'] else 'fuzzy'))
    items = []
    for r in found:
        score, match = r.pop('_score'), r.pop('_match')
        for k in [k for k in r if k.startswith('_') or re.fullmatch(r'(?:te|se|wt|ws)\d',k)]: r.pop(k)
        item = resolve(db, r, deadline); item['score'] = round(float(score), 2); item['match'] = match
        items.append(item)
    return items

def validate_links(db, links, token=None):
    if links is None: return []
    if not isinstance(links,list) or len(links)>100: fail('links must be an array of at most 100 entries')
    result=[]
    for link in links:
        if not isinstance(link,dict) or set(link)-{'rel','to','note'} or not isinstance(link.get('rel'),str) or link['rel'] not in RELS:
            fail('invalid link')
        target=lookup(db,link.get('to'),reserved=True)
        if not target: fail('link target not allocated',409)
        require_surface(token,target['surface'])
        note=link.get('note')
        if note is not None: text_field(note,'link note',1200); pointer_guard(note); guard(note,True)
        result.append((link['rel'],target['id'],note))
    return result

def resolve(db,row,deadline=None,depth=0):
    row = dict(row); row.pop('search',None)
    aid = row['id']; row['id']='a#'+aid
    parent = db.execute('SELECT id,title FROM artifact WHERE id=%s',(row['parent'],)).fetchone() if row['parent'] else None
    if parent: parent['id']='a#'+parent['id']
    row['parent']=parent
    row['children']=db.execute("SELECT id,title,kind FROM artifact WHERE parent=%s AND status='active' ORDER BY id",(aid,)).fetchall()
    for child in row['children']: child['id']='a#'+child['id']
    row['refs']=db.execute('SELECT kind,target,label,pinned_sha,ord,origin FROM artifact_ref WHERE artifact_id=%s ORDER BY ord',(aid,)).fetchall()
    row['aliases']=[r['alias'] for r in db.execute('SELECT alias FROM artifact_alias WHERE artifact_id=%s ORDER BY alias',(aid,))]
    row['stale']=bool(row['sync_source'] and (not row['last_verified'] or row['last_verified']<datetime.now(timezone.utc)-timedelta(days=7)))
    row['links']=db.execute("SELECT rel,'a#'||dst AS to,note FROM artifact_link l JOIN artifact a ON a.id=l.dst WHERE src=%s AND a.status!='reserved' ORDER BY rel,dst",(aid,)).fetchall()
    if depth:
        visited={aid}; frontier=[aid]; nodes=[]
        for _ in range(depth):
            next_frontier=[]
            for src in frontier:
                for node in db.execute("SELECT a.id,a.title,a.summary,a.kind,a.status FROM artifact_link l JOIN artifact a ON a.id=l.dst WHERE src=%s AND a.status!='reserved' ORDER BY a.id",(src,)):
                    if node['id'] in visited or len(nodes)>=12: continue
                    visited.add(node['id']); next_frontier.append(node['id'])
                    node['id']='a#'+node['id']; nodes.append(node)
            frontier=next_frontier
        row['linked_nodes']=nodes
    if row.get('superseded_by'): row['superseded_by']='a#'+row['superseded_by']
    if row['kind']=='session':
        row['howto']=f"Trace lesen: desk-trace a#{aid} (--json, --raw, --diagnosis-only) oder GET /v1/sessions/{aid}/trace und /diagnosis mit dem Agent-Token. Board-Beitraege mit --artifact a#{aid} verknuepfen."
    row['stale'] = bool(row.get('stale_reason')) or row['stale'] or any(sha_missing(ref,deadline or time.monotonic()+2) for ref in row['refs'])
    return row

def generation_key(value, check_future=False):
    key = None
    if type(value) is int and 0 <= value < 10**20: key = (value,'')
    if isinstance(value,str):
        match=re.fullmatch(r'(\d{1,20})(?::([0-9a-f]{7,64}))?',value)
        if match: key = (int(match[1]),match[2] or '')
    if key is None: fail('generation must be a nonnegative commit timestamp or timestamp:sha')
    if check_future and key[0] > time.time()+86400: fail('generation exceeds now plus one day')
    return key

def sync(db,b,actor,token=None):
    surface=text_field(b.get('surface'),'surface',200,False)
    require_surface(token,surface)
    source=text_field(b.get('sync_source'),'sync_source',4096,False)
    sha=b.get('sha')
    if sha is not None and (not isinstance(sha,str) or not re.fullmatch(r'[0-9a-f]{7,64}',sha)): fail('invalid sha')
    generation=b.get('generation')
    key=generation_key(generation,check_future=True)
    state=db.execute('SELECT generation FROM sync_state WHERE surface=%s AND sync_source=%s FOR UPDATE',(surface,source)).fetchone()
    if state and key<=generation_key(state['generation']): fail('stale_generation',409)
    items=b.get('items')
    if isinstance(items,dict): items=list(items.values())
    if not isinstance(items,list) or len(items)>1000: fail('items must be an array or component map with at most 1000 entries')
    if type(b.get('allow_shrink',False)) is not bool: fail('allow_shrink must be boolean')
    previous=db.execute("SELECT count(*) AS n FROM artifact WHERE surface=%s AND sync_source=%s AND status='active'",(surface,source)).fetchone()['n']
    if (not items or len(items)<previous/2) and not b.get('allow_shrink',False): fail('shrink_refused',409)
    pending=[]; ids=[]; aliases={}
    for raw in items:
        if not isinstance(raw,dict) or not raw.get('id'): fail('sync items require stable ids')
        aid=id_value(raw['id'])
        if aid in ids: fail('duplicate manifest id')
        old=db.execute('SELECT surface,sync_source FROM artifact WHERE id=%s',(aid,)).fetchone()
        if not old: fail('not_allocated',409)
        if old['surface']!=surface or raw.get('surface',surface)!=surface or old['sync_source'] not in (None,source): fail('owner_mismatch',409)
        item=dict(raw,surface=surface,sync_source=source,status='active',deployed_rev=sha)
        item.setdefault('refs',[])
        if isinstance(item['refs'],list):
            item['refs']=[dict(r) if isinstance(r,dict) else r for r in item['refs']]
            for ref in item['refs']:
                if isinstance(ref,dict) and ref.get('kind')=='code' and sha:
                    ref['target']=re.sub(r'@(?:HEAD|main)(?=:)', '@'+sha,text_field(ref.get('target'),'ref target',4096,False))
                    ref['pinned_sha']=sha
        if 'aliases' in item:
            if not isinstance(item['aliases'],list): fail('aliases must be an array')
            for alias in item['aliases']:
                alias=text_field(alias,'alias',300,False).strip().lower()
                if alias in aliases and aliases[alias]!=aid: fail('alias_taken',409)
                aliases[alias]=aid
        ids.append(aid); pending.append(item)
    # Resolve aliases declared later in the same manifest before validation/writes.
    for item in pending:
        if 'links' in item and isinstance(item['links'],list):
            item['links']=[dict(link,to=aliases.get(str(link.get('to','')).lower(),link.get('to'))) if isinstance(link,dict) else link for link in item['links']]
    # Validate the final parent graph, including unchanged ancestors, before writes.
    parents={id_value(i['id']):i.get('parent',db.execute('SELECT parent FROM artifact WHERE id=%s',(id_value(i['id']),)).fetchone()['parent']) for i in pending}
    for start in parents:
        seen=set(); current=start
        while current is not None:
            current=id_value(current)
            if current in seen: fail('manifest parent cycle')
            seen.add(current)
            if current in parents: current=parents[current]
            else:
                row=db.execute('SELECT parent FROM artifact WHERE id=%s',(current,)).fetchone()
                if not row: fail('parent not allocated',409)
                current=row['parent']
    ordered=[]
    while pending:
        waiting={id_value(p['id']) for p in pending}
        ready=[i for i in pending if not i.get('parent') or id_value(i['parent']) not in waiting]
        if not ready: fail('manifest parent cycle')
        for item in ready:
            upsert(db,item,actor,origin='manifest',validate_only=True,token=token)
            ordered.append(item); pending.remove(item)
    for item in ordered:
        aid=upsert(db,item,actor,origin='manifest',token=token)
        db.execute('UPDATE artifact SET last_verified=now(),last_synced=now() WHERE id=%s',(aid,))
    retired=db.execute("UPDATE artifact SET status='retired',updated_at=now() WHERE surface=%s AND sync_source=%s AND status='active' AND NOT(id=ANY(%s::text[])) RETURNING id",(surface,source,ids)).fetchall()
    db.execute('INSERT INTO sync_state(surface,sync_source,generation,sha) VALUES(%s,%s,%s,%s) ON CONFLICT(surface,sync_source) DO UPDATE SET generation=EXCLUDED.generation,sha=EXCLUDED.sha,at=now()',(surface,source,str(generation),sha))
    audit(db,actor,'sync',detail={'count':len(ids),'retired':len(retired)})
    return {'ids':['a#'+i for i in ids],'retired':['a#'+r['id'] for r in retired]}

SESSION_ID = re.compile(r'/v1/sessions/([0-9a-f]{6})/(trace|diagnosis|events)')
SLUG = re.compile(r'[\w .:/@#+-]{1,200}')

def session_row(db, aid, lock=False):
    row = db.execute("SELECT m.*,a.title,a.status FROM session_meta m JOIN artifact a ON a.id=m.session_id WHERE m.session_id=%s"+(' FOR UPDATE OF m' if lock else ''),(aid,)).fetchone()
    if not row: fail('session not found',404)
    return row

def session_public(row):
    row = dict(row); row['id'] = 'a#'+row.pop('session_id')
    return row

def session_events(db, aid, limit=20000, source=None):
    return db.execute("SELECT seq,ts,source,turn,type,data FROM session_trace WHERE session_id=%s"+(" AND source=%s" if source else "")+" ORDER BY ts,source,seq LIMIT %s",(aid,)+((source,) if source else ())+(limit,)).fetchall()

def session_refresh(db, aid):
    """Recompute the diagnosis; flag unanswered sessions and keep the artifact summary current."""
    meta = session_row(db,aid,lock=True)
    diag = S.diagnose(dict(meta,id='a#'+aid),session_events(db,aid))
    if diag['flagged'] and (not meta['flagged'] or (meta['flag_sent_at'] is None and meta['flag_reason']!=diag['flag_reason'])):
        db.execute('UPDATE session_meta SET flagged=true,flag_reason=%s WHERE session_id=%s',(diag['flag_reason'],aid))
    db.execute('UPDATE artifact SET summary=%s,updated_at=now() WHERE id=%s',(S.summary_for(diag)[:1200],aid))
    return diag

def device_day_start(moment):
    """Start of the Berlin calendar day, as UTC."""
    local = local_time(moment)
    return local.replace(hour=0,minute=0,second=0,microsecond=0).astimezone(timezone.utc)

def local_time(moment):
    try: return moment.astimezone(ZoneInfo('Europe/Berlin'))
    except ZoneInfoNotFoundError: return moment

def session_create(db, b, actor, token):
    require_surface(token,'desk:sessions')
    kind = b.get('kind')
    if kind not in ('voice','chat','device'): fail('kind must be voice, chat or device')
    provider = text_field(b.get('provider'),'provider',40,False)
    if not re.fullmatch(r'[\w.-]+',provider): fail('invalid provider')
    meta = {}
    for name,limit in (('model',100),('slug',200),('device',200),('gateway_commit',64)):
        value = b.get(name)
        meta[name] = None if value is None else text_field(value,name,limit)
    if meta['slug'] is not None and not SLUG.fullmatch(meta['slug']): fail('invalid slug')
    for name in ('client','entry'):
        value = b.get(name,{})
        if not isinstance(value,dict) or len(json.dumps(value))>4096: fail(name+' must be a small object')
        meta[name],_ = S.scrub(value,SECRET)
    screens = b.get('screen_ids',[])
    if not isinstance(screens,list) or len(screens)>20: fail('screen_ids must be an array of at most 20 ids')
    now = datetime.now(timezone.utc)
    if kind=='device':  # one trace per day: the gateway may ask again after every restart
        today = db.execute("SELECT session_id FROM session_meta WHERE kind='device' AND started_at>=%s ORDER BY started_at DESC LIMIT 1",(device_day_start(now),)).fetchone()
        if today: return {'id':today['session_id']}
    aid = allocate(db,'desk:sessions',actor)
    db.execute("UPDATE artifact SET kind='session',title=%s,status='active',access='private',updated_at=now() WHERE id=%s",(S.title_for(kind,provider,local_time(now)),aid))
    db.execute('INSERT INTO session_meta(session_id,kind,provider,model,slug,device,client,entry,gateway_commit,started_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
               (aid,kind,provider,meta['model'],meta['slug'],meta['device'],Jsonb(meta['client']),Jsonb(meta['entry']),meta['gateway_commit'],now))
    db.execute("INSERT INTO artifact_ref(artifact_id,kind,target,label,ord) VALUES(%s,'endpoint',%s,'Trace',0)",(aid,f'/v1/sessions/{aid}/trace'))
    targets = [b.get('page_aid'),b.get('card'),b.get('element')]+screens
    for value in targets:
        if value in (None,'') or not isinstance(value,(str,int)): continue
        try: row = lookup(db,str(value),reserved=True)
        except APIError: row = None
        if not row or row['id']==aid: continue
        for src,dst in ((aid,row['id']),(row['id'],aid)):
            db.execute("INSERT INTO artifact_link(src,dst,rel,created_by) VALUES(%s,%s,'related',%s) ON CONFLICT DO NOTHING",(src,dst,actor))
    audit(db,actor,'session_create',aid)
    return {'id':aid}

def session_ingest(db, aid, b, actor, token):
    require_surface(token,'desk:sessions')
    session_row(db,aid)
    events = b.get('events')
    if not isinstance(events,list) or not events: fail('events must be a non-empty array')
    if len(events)>S.MAX_BATCH: fail(f'at most {S.MAX_BATCH} events per batch',413)
    rows = []; dropped = truncated = 0; kinds = set()
    for n,event in enumerate(events):
        try:
            if not isinstance(event,dict) or set(event)-{'seq','ts','source','turn','type','data'}: raise ValueError
            seq,turn,source,etype,data = event['seq'],event.get('turn'),event.get('source'),event.get('type'),event.get('data',{})
            if type(seq) is not int or not 0<=seq<2**53 or (turn is not None and (type(turn) is not int or not 0<=turn<2**31)): raise ValueError
            if not isinstance(source,str) or not re.fullmatch(r'[a-z0-9._-]{1,40}',source) or not isinstance(etype,str) or not re.fullmatch(r'[a-z][a-z0-9._-]{0,59}',etype): raise ValueError
            if data is None: data = {}
            if not isinstance(data,dict): raise ValueError
            ts = S.clamp_ts(S.parse_ts(event['ts']),datetime.now(timezone.utc))
        except (ValueError,KeyError,TypeError,OverflowError,OSError): fail(f'invalid event at index {n}')
        data,was_dropped = S.scrub(data,SECRET)
        size = len(json.dumps(data,ensure_ascii=False).encode())
        if size>S.MAX_EVENT_BYTES: data = {'truncated':True,'bytes':size}; truncated += 1
        if was_dropped: data['dropped'] = True; dropped += 1
        rows.append((aid,seq,ts,source,turn,etype,Jsonb(data))); kinds.add(etype)
    inserted = 0
    with db.cursor() as cur:
        for row in rows:
            cur.execute('INSERT INTO session_trace(session_id,seq,ts,source,turn,type,data) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING',row)
            inserted += cur.rowcount
    stops = [r[2] for r in rows if r[5]=='session.stop']
    if stops: db.execute('UPDATE session_meta SET ended_at=%s WHERE session_id=%s AND ended_at IS NULL',(max(stops),aid))
    if kinds & {'session.stop','turn.unanswered','watchdog.no_answer'}: session_refresh(db,aid)
    return {'accepted':inserted,'duplicates':len(rows)-inserted,'dropped':dropped,'truncated':truncated}

def session_api(db, command, path, q, b, actor, token):
    if path=='/v1/sessions' and command=='POST': return session_create(db,b,actor,token)
    if path=='/v1/sessions/lookup' and command=='GET':
        value = text_field(q.get('q',[''])[0],'q',300,False).strip()
        low = value.lower()
        chat = "kind IN ('voice','chat')"  # last, previous and slugs never land on a device trace
        if low in ('last','previous'):
            skip = q.get('exclude',[''])[0]
            try: skip = normalise(skip) if skip else None
            except ValueError: fail('invalid exclude id')
            row = db.execute(f'SELECT session_id FROM session_meta WHERE {chat} AND session_id IS DISTINCT FROM %s ORDER BY started_at DESC LIMIT 1',(skip,)).fetchone()
        elif low=='device': row = db.execute("SELECT session_id FROM session_meta WHERE kind='device' AND started_at>=%s ORDER BY started_at DESC LIMIT 1",(device_day_start(datetime.now(timezone.utc)),)).fetchone()
        else:
            try: row = {'session_id':normalise(value)}
            except ValueError: row = db.execute(f'SELECT session_id FROM session_meta WHERE {chat} AND lower(slug)=%s ORDER BY started_at DESC LIMIT 1',(low,)).fetchone()
        if not row: fail('session not found',404)
        return session_public(session_row(db,row['session_id']))
    if path=='/v1/sessions/recent' and command=='GET':
        get = lambda key: q.get(key,[''])[0]
        try: limit = int(get('limit') or 10)
        except ValueError: fail('limit must be an integer')
        if not 1<=limit<=50: fail('limit must be between 1 and 50')
        kind = get('kind') or 'chat+voice'
        if kind not in ('voice','chat','device','chat+voice','all'): fail('kind must be voice, chat, device or all')
        where = ['TRUE']; vals = []
        if kind!='all': where.append('m.kind=ANY(%s)'); vals.append(['voice','chat'] if kind=='chat+voice' else [kind])
        for name,clause in (('before','m.started_at<%s'),('around',"(m.started_at BETWEEN %s-interval '30 minutes' AND %s+interval '30 minutes' OR (m.started_at<=%s AND coalesce(m.ended_at,m.started_at+interval '6 hours')>=%s))")):
            if get(name):
                try: moment = S.parse_ts(get(name))
                except ValueError: fail(name+' must be an ISO time')
                where.append(clause); vals += [moment]*clause.count('%s')
        rows = db.execute('SELECT m.session_id,a.title,m.kind,m.provider,m.started_at,m.ended_at,m.flagged,a.summary FROM session_meta m JOIN artifact a ON a.id=m.session_id WHERE '+' AND '.join(where)+' ORDER BY m.started_at DESC LIMIT %s',vals+[limit]).fetchall()
        return {'items':[{'id':'a#'+r['session_id'],'title':r['title'],'kind':r['kind'],'provider':r['provider'],'started_at':r['started_at'],'ended_at':r['ended_at'],'flagged':r['flagged'],'summary':r['summary']} for r in rows]}
    if path=='/v1/sessions/flags' and command=='GET':
        rows = db.execute('SELECT session_id,flag_reason FROM session_meta WHERE flagged AND flag_sent_at IS NULL ORDER BY started_at LIMIT 200').fetchall()
        return {'items':[{'id':'a#'+r['session_id'],'reason':r['flag_reason']} for r in rows]}
    if path=='/v1/sessions/flags/sent' and command=='POST':
        ids = b.get('ids')
        if not isinstance(ids,list) or not ids or len(ids)>200: fail('ids must be a non-empty array of at most 200 ids')
        try: ids = [normalise(str(v)) for v in ids]
        except ValueError: fail('invalid session id')
        rows = db.execute('UPDATE session_meta SET flag_sent_at=now() WHERE session_id=ANY(%s) AND flagged AND flag_sent_at IS NULL RETURNING session_id',(ids,)).fetchall()
        audit(db,actor,'session_flags_sent')
        return {'marked':len(rows)}
    match = SESSION_ID.fullmatch(path)
    if not match: fail('endpoint not found',404)
    aid,what = match.groups()
    if what=='events' and command=='POST': return session_ingest(db,aid,b,actor,token)
    if command!='GET': fail('endpoint not found',404)
    meta = session_row(db,aid)
    if what=='trace':
        try: limit = int(q.get('limit',['20000'])[0])
        except ValueError: fail('limit must be an integer')
        if not 1<=limit<=20000: fail('limit must be between 1 and 20000')
        events = session_events(db,aid,limit,q.get('source',[None])[0])
        return {'session':session_public(meta),'count':len(events),'events':events}
    return {'session':session_public(meta),'diagnosis':S.diagnose(dict(meta,id='a#'+aid),session_events(db,aid))}

class Handler(BaseHTTPRequestHandler):
    server_version='ArtifactRegistry/1'
    def log_message(self,*args): pass
    def reply(self,status,data):
        raw=json.dumps(data,default=lambda x:str(x) if isinstance(x,uuid.UUID) else x.isoformat(),ensure_ascii=False).encode()
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(raw)
    def do_GET(self): self.handle_api()
    def do_POST(self): self.handle_api()
    def do_PUT(self): self.handle_api()
    def do_DELETE(self): self.handle_api()
    def handle_api(self):
        status=500; actor=None
        try:
            self.connection.settimeout(15)
            parsed=urlsplit(self.path); path=parsed.path
            self.sha_deadline=time.monotonic()+2
            if self.command=='GET' and path=='/healthz':
                status=200; self.reply(200,{'ok':True}); return
            if self.command=='GET' and path.startswith('/static/'):
                # Exact allowlist: never map a request path onto the filesystem.
                assets={'/static/artifact-badge.js':'text/javascript',
                        '/static/artifact-badge.css':'text/css'}
                if path not in assets: fail('asset not found',404)
                raw=(Path(__file__).parent/'web'/path.rsplit('/',1)[1]).read_bytes()
                status=200
                self.send_response(status)
                self.send_header('Content-Type',assets[path]+'; charset=utf-8')
                self.send_header('Content-Length',str(len(raw)))
                self.send_header('Cache-Control','public, max-age=3600')
                self.send_header('Access-Control-Allow-Origin','*')
                self.send_header('X-Content-Type-Options','nosniff')
                self.end_headers(); self.wfile.write(raw); return
            auth=self.headers.get('Authorization','')
            if not auth.startswith('Bearer ') or not auth[7:].strip() or len(auth)>512: fail('bearer token required',401)
            digest=hashlib.sha256(auth[7:].encode()).hexdigest()
            if not self.server.connections.acquire(blocking=False): fail('registry connection capacity reached',503)
            try:
                self.authenticated_request(parsed,path,digest)
                status=200
            finally:
                self.server.connections.release()
            return
        except APIError as e:
            status=e.status; self.close_connection=True; self.reply(status,{'error':e.message})
        except psycopg.IntegrityError as e:
            alias_error='alias' in (e.diag.constraint_name or '') or e.diag.message_primary=='alias_taken'
            status=409; self.close_connection=True; self.reply(status,{'error':'alias_taken' if alias_error else 'constraint conflict (parent or alias)'})
        except (psycopg.Error,OSError):
            status=503; self.close_connection=True; self.reply(status,{'error':'registry unavailable'})
        except Exception:
            status=500; self.close_connection=True; self.reply(status,{'error':'internal registry error'})
        finally:
            print(json.dumps({'method':self.command,'status':status,'actor':getattr(self,'actor',actor)}),flush=True)
    def authenticated_request(self,parsed,path,digest):
        with psycopg.connect(self.server.dsn,row_factory=dict_row) as db:
            token=self.server.authenticate(db,digest)
            if not token: fail('invalid bearer token',401)
            self.token=token
            self.actor=token['name']
            scope=('sync' if path=='/v1/sessions/flags/sent' else 'trace' if path.startswith('/v1/sessions') and self.command!='GET' else 'devices' if path=='/v1/devices' or path.startswith('/v1/devices/') else 'dict' if path.startswith('/v1/dictionary/') else 'admin' if path=='/v1/admin/sync-reset' else 'sync' if path=='/v1/sync' else 'dict' if path=='/v1/dictionary' else 'read' if self.command=='GET' else 'write')
            if scope not in token['scopes']: fail('insufficient scope: '+scope,403)
            body={}
            if self.command!='GET':
                if self.headers.get('Transfer-Encoding'): fail('transfer encoding not supported',400)
                try: length=int(self.headers.get('Content-Length','0'))
                except ValueError: fail('invalid content length',400)
                if length<0 or length>(MAX_EVENTS_BODY if path.endswith('/events') else MAX_BODY): fail('body too large',413)
                try: body=json.loads(self.rfile.read(length)) if length else {}
                except (ValueError,UnicodeError): fail('invalid JSON body',400)
                if not isinstance(body,dict): fail('JSON body must be an object')
                db.execute('SELECT pg_advisory_xact_lock(734927100)')
            result=self.dispatch(db,path,parse_qs(parsed.query),body,token['name'])
        self.reply(200,result)
    def dispatch(self,db,path,q,b,actor):
        get=lambda key,default='':q.get(key,[default])[0]
        if path=='/v1/devices' and self.command=='GET':
            return {'devices':db.execute("SELECT id,label,scopes,created_at,expires_at,revoked_at,last_seen FROM device WHERE revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 1000").fetchall()}
        if path in ('/v1/devices','/v1/devices/verify') and self.command=='POST':
            digest=b.get('hash')
            if not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest): fail('invalid device hash')
            if path.endswith('/verify'):
                row=db.execute("SELECT id,scopes,expires_at,last_seen FROM device WHERE hash=%s AND revoked_at IS NULL AND expires_at>now()",(digest,)).fetchone()
                if not row: fail('device not found',404)
                db.execute("UPDATE device SET last_seen=now() WHERE id=%s AND (last_seen IS NULL OR last_seen<now()-interval '1 minute')",(row['id'],))
                row.pop('last_seen',None)
                return row
            label=text_field(b.get('label'),'label',100,False)
            guard(label)
            scopes=b.get('scopes')
            if not isinstance(scopes,list) or not scopes or len(scopes)>4 or any(not isinstance(v,str) or v not in {'dictate','dictionary','screen','exists'} for v in scopes): fail('invalid device scopes')
            expiry=b.get('expires_at')
            if type(expiry) is not int: fail('expires_at must be Unix milliseconds')
            current=int(time.time()*1000)
            if not current<expiry<=current+90*86400000+60000: fail('invalid device expiry')
            if db.execute("SELECT count(*) AS n FROM device WHERE revoked_at IS NULL AND expires_at>now()").fetchone()['n']>=1000: fail('device limit reached',429)
            did=uuid.uuid4()
            db.execute('INSERT INTO device(id,hash,label,scopes,expires_at) VALUES(%s,%s,%s,%s,%s)',(did,digest,label,list(dict.fromkeys(scopes)),datetime.fromtimestamp(expiry/1000,timezone.utc)))
            audit(db,actor,'device_create')
            return {'id':str(did)}
        if path.startswith('/v1/devices/') and self.command=='DELETE':
            try: did=uuid.UUID(path.removeprefix('/v1/devices/'))
            except ValueError: fail('invalid device id')
            row=db.execute('UPDATE device SET revoked_at=coalesce(revoked_at,now()) WHERE id=%s RETURNING id',(did,)).fetchone()
            if not row: fail('device not found',404)
            audit(db,actor,'device_revoke')
            return {'ok':True}
        if path.startswith('/v1/dictionary/') and self.command=='DELETE':
            term=text_field(unquote(path.removeprefix('/v1/dictionary/')),'term',200,False)
            row=db.execute("DELETE FROM dictionary WHERE term=%s AND source='learned' RETURNING term",(term,)).fetchone()
            if not row: fail('learned term not found',404)
            audit(db,actor,'dictionary_delete')
            return {'ok':True}
        if path.startswith('/v1/sessions'): return session_api(db,self.command,path,q,b,actor,self.token)
        if self.command=='GET':
            if path in ('/v1/resolve','/v1/exists'):
                ids=get('ids').split(',') if get('ids') else []
                if len(ids)>100: fail('maximum 100 ids')
                try: depth=int(get('depth','0'))
                except ValueError: fail('depth must be 0, 1 or 2')
                if depth not in (0,1,2): fail('depth must be 0, 1 or 2')
                items=[]; known=[]; unknown=[]
                for value in ids:
                    row=lookup(db,value)
                    if row:
                        known.append('a#'+row['id'])
                        if path.endswith('resolve'): items.append(resolve(db,row,self.sha_deadline,depth))
                    else: unknown.append(value)
                return {'known':list(dict.fromkeys(known))} if path.endswith('exists') else {'items':items,'unknown':unknown}
            if path in ('/v1/search','/v1/list'):
                try: limit=int(get('limit','50'))
                except ValueError: fail('limit must be an integer')
                if not 1<=limit<=200: fail('limit must be between 1 and 200')
                narrow={key:get(key) for key in ('surface','kind') if get(key)}
                if path.endswith('search'):
                    return {'items':search(db,text_field(get('q'),'q',500),narrow,limit,self.sha_deadline)}
                filters=["status='active'"]+[key+'=%s' for key in narrow]
                rows=db.execute('SELECT * FROM artifact WHERE '+' AND '.join(filters)+' ORDER BY updated_at DESC,id LIMIT %s',list(narrow.values())+[limit]).fetchall()
                return {'items':[resolve(db,r,self.sha_deadline) for r in rows]}
            if path=='/v1/verify-refs':
                after=get('after')
                if after: after=id_value(after)
                rows=db.execute("SELECT id FROM artifact WHERE id>%s AND status='active' AND EXISTS(SELECT 1 FROM artifact_ref WHERE artifact_id=artifact.id AND kind='code') ORDER BY id LIMIT 200",(after,)).fetchall()
                for row in rows:
                    row['refs']=db.execute("SELECT kind,target,pinned_sha FROM artifact_ref WHERE artifact_id=%s AND kind='code' ORDER BY target",(row['id'],)).fetchall()
                return {'items':rows}
            if path=='/v1/dictionary':
                return {'items':db.execute('SELECT * FROM dictionary ORDER BY weight DESC,term').fetchall()}
        if self.command=='POST' and path=='/v1/verify-refs':
            aid=id_value(b.get('id'))
            row=lookup(db,aid,reserved=True)
            if not row: fail('not_allocated',409)
            require_surface(self.token,row['surface'])
            refs=db.execute("SELECT kind,target,pinned_sha FROM artifact_ref WHERE artifact_id=%s AND kind='code' ORDER BY target",(aid,)).fetchall()
            if not refs or refs!=b.get('refs'): fail('refs_changed',409)
            reason=b.get('stale_reason')
            if reason is not None: text_field(reason,'stale_reason',1200); guard(reason,True)
            db.execute('UPDATE artifact SET refs_verified_at=now(),stale_reason=%s WHERE id=%s',(reason,aid))
            audit(db,actor,'verify_refs',aid)
            return {'id':'a#'+aid}
        if self.command=='POST' and path=='/v1/ids':
            count=b.get('count',1)
            if type(count)!=int or not 1<=count<=200: fail('count must be between 1 and 200')
            surface=text_field(b.get('surface'),'surface',200,False)
            require_surface(self.token,surface)
            return {'ids':['a#'+allocate(db,surface,actor) for _ in range(count)]}
        if (self.command=='POST' and path=='/v1/artifacts') or (self.command=='PUT' and path.startswith('/v1/artifacts/')):
            if self.command=='PUT':
                aid=id_value(path.removeprefix('/v1/artifacts/'))
                if b.get('id') and id_value(b['id'])!=aid: fail('path/body id mismatch')
                b['id']=aid
            aid=upsert(db,b,actor,token=self.token)
            return {'id':'a#'+aid}
        if self.command=='POST' and path=='/v1/admin/sync-reset':
            surface=text_field(b.get('surface'),'surface',200,False)
            source=text_field(b.get('sync_source'),'sync_source',4096,False)
            require_surface(self.token,surface)
            db.execute('DELETE FROM sync_state WHERE surface=%s AND sync_source=%s',(surface,source))
            audit(db,actor,'sync_reset',detail={'surface':surface,'sync_source':source})
            return {'reset':True}
        if self.command=='POST' and path=='/v1/sync':
            return sync(db,b,actor,token=self.token)
        if self.command=='POST' and path=='/v1/dictionary':
            term=text_field(b.get('term'),'term',200,False); guard(term)
            replacements=b.get('replace_from',[])
            if not isinstance(replacements,list) or len(replacements)>40: fail('invalid replace_from')
            for replacement in replacements: text_field(replacement,'replace_from',200,False); guard(replacement)
            source=b.get('source','manual')
            if not isinstance(source,str) or source not in {'wispr','harvest','learned','manual'}: fail('invalid dictionary source')
            db.execute("INSERT INTO dictionary(term,replace_from,source) VALUES(%s,%s,%s) ON CONFLICT(term) DO UPDATE SET replace_from=(SELECT ARRAY(SELECT DISTINCT unnest(dictionary.replace_from || EXCLUDED.replace_from))),source=CASE WHEN dictionary.source='learned' THEN EXCLUDED.source ELSE dictionary.source END",(term,replacements,source))
            audit(db,actor,'dictionary')
            return {'term':term}
        fail('endpoint not found',404)

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,dsn):
        self.dsn=dsn
        self.connections=threading.BoundedSemaphore(8)
        self.token_cache={}
        self.token_lock=threading.Lock()
        super().__init__(address,Handler)

    def authenticate(self,db,digest):
        with self.token_lock:
            cached=self.token_cache.get(digest)
            if cached and cached[0]>time.monotonic(): return cached[1]
        token=None
        for row in db.execute('SELECT name,hash,scopes,surfaces FROM token'):
            if hmac.compare_digest(digest,row['hash']): token=row
        with self.token_lock:
            if len(self.token_cache)>=4096: self.token_cache.clear()
            self.token_cache[digest]=(time.monotonic()+60,token)
        return token

def trace_retention_loop(dsn, days, interval=86400, first=300):
    """Daily 30-day trace retention inside the service, so no external writer needs database access."""
    time.sleep(first)
    while True:
        try:
            with psycopg.connect(dsn) as db:
                removed=db.execute('SELECT session_trace_retention(%s)',(days,)).fetchone()[0]
            print(json.dumps({'job':'session_trace_retention','days':days,'removed':removed}),flush=True)
        except Exception as e:
            print(json.dumps({'job':'session_trace_retention','error':type(e).__name__}),flush=True)
        time.sleep(interval)

def main():
    dsn=os.environ['ARTIFACTS_DATABASE_URL']
    days=int(os.getenv('ARTIFACTS_TRACE_RETENTION_DAYS','30'))
    if days>0: threading.Thread(target=trace_retention_loop,args=(dsn,days),daemon=True).start()
    Server((os.getenv('ARTIFACTS_BIND','0.0.0.0'),int(os.getenv('PORT','8080'))),dsn).serve_forever()
if __name__=='__main__': main()
