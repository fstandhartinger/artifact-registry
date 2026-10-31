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
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg import sql
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'bin'))
from artifact_ids import normalise

MAX_BODY = 256 * 1024
BIP39_WORDS = frozenset((Path(__file__).parent/'data/bip39-english.txt').read_text().splitlines())
KINDS = {'app','page','panel','element','card','explainer','scene','diagram','doc','job','tweet','board-entry','finance'}
REF_KINDS = {'code','repo','file','board','decision','readme','doc','endpoint','url','job','card','explainer','artifact'}
SECRET = re.compile(r'(?i)(?:\b(?:sk-|(?:ghp|github_pat|gho|art|hf)_|xox[baprs]-)[a-z0-9_-]{8,}|\bAKIA[A-Z0-9]{16}\b|\bbearer\s+\S+|\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:password|passwd|api[_ -]?key|access[_ -]?token|secret[_ -]?key)\s*[:=]\s*\S+|\b(?:seed phrase|recovery phrase|mnemonic)\b|\b[a-z]{2}\d{2}(?:[ \t]?[a-z0-9]){11,30}\b)')
AMOUNT = re.compile(r'(?i)(?:[$€£¥₹₿αΞ]|\b(?:EUR|USD|GBP|CHF|JPY|CNY|CAD|AUD|INR|TAO|BTC|ETH|USDT|USDC|SOL|BNB|REAX)\b)\s*[-+]?\s*[\d., ]*\d|\d[\d., ]*\s*(?:[$€£¥₹₿αΞ]|\b(?:EUR|USD|GBP|CHF|JPY|CNY|CAD|AUD|INR|TAO|BTC|ETH|USDT|USDC|SOL|BNB|REAX)\b)')
RELS = {'related','explains','explained_by','discussed_in','decided_by','supersedes','superseded_by','depends_on','shows_data_of'}
INVERSE = {'explains':'explained_by','explained_by':'explains','supersedes':'superseded_by','superseded_by':'supersedes'}
FIELDS = {'superseded_by','deployed_rev','kind','title','summary','surface','owner_job','parent','url','selector','access','status','sync_source'}

# SHA checks have a shared two-second budget per request. Fail closed as stale on
# network errors/rate limits, and cache results for 15 minutes (one minute on errors).
_SHA_CACHE = {}
_SHA_LOCK = threading.Lock()

def sha_missing(ref, deadline):
    if ref['kind'] not in {'code','repo'}:
        return False
    match = re.fullmatch(r'github:([\w.-]+)/([\w.-]+)(?:@([^:]+))?(?::.*)?',ref['target'])
    if not match:
        return bool(ref.get('pinned_sha'))
    owner, repo, rev = match.groups()
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
        return True
    missing = True; ttl = 60
    try:
        req = urllib.request.Request('https://api.github.com/repos/'+owner+'/'+repo+'/git/commits/'+sha,
                                     headers={'Accept':'application/vnd.github+json','User-Agent':'artifact-registry'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs): return None
        with urllib.request.build_opener(NoRedirect).open(req, timeout=min(1.5,remaining)) as response:
            missing = response.status != 200
            ttl = 900
    except urllib.error.HTTPError as error:
        if error.code in (404,410,422): ttl = 900
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
    if SECRET.search(value):
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

def allocate(db, surface, actor):
    for _ in range(5):
        aid = secrets.token_hex(3)
        row = db.execute("INSERT INTO artifact(id,kind,title,surface,status) VALUES(%s,'element','',%s,'reserved') ON CONFLICT DO NOTHING RETURNING id", (aid,surface)).fetchone()
        if row:
            audit(db,actor,'reserve',aid)
            return aid
    fail('id allocation conflict; retry',409)

def upsert(db, item, actor, origin="agent", validate_only=False):
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
    if old and old['surface'] != data['surface']:
        fail('owner_mismatch',409)
    for name in ('owner_job','url','selector','sync_source','deployed_rev'):
        if data.get(name) is not None:
            text_field(data[name],name,4096)
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
    finance = data['surface'].startswith('app:') or data['kind'] in {'finance','panel','element','card'}
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
            text_field(ref.get('target'),'ref target',4096,False)
            # Credentials are forbidden in pointers too (including URL userinfo/query tokens).
            if SECRET.search(ref['target']) or re.search(r'(?i)https?://[^/\s]+@|[?&](?:token|key|secret|password)=',ref['target']):
                fail('reference contains a possible credential')
            for field in ('label','pinned_sha'):
                if ref.get(field) is not None:
                    text_field(ref[field],field,500)
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
    links = validate_links(db,item.get('links'))
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
        db.execute('DELETE FROM artifact_ref WHERE artifact_id=%s AND origin=%s',(aid,origin))
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

def validate_links(db, links):
    if links is None: return []
    if not isinstance(links,list) or len(links)>100: fail('links must be an array of at most 100 entries')
    result=[]
    for link in links:
        if not isinstance(link,dict) or set(link)-{'rel','to','note'} or not isinstance(link.get('rel'),str) or link['rel'] not in RELS:
            fail('invalid link')
        target=lookup(db,link.get('to'),reserved=True)
        if not target: fail('link target not allocated',409)
        note=link.get('note')
        if note is not None: text_field(note,'link note',1200); guard(note,True)
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
    row['stale'] = bool(row.get('stale_reason')) or row['stale'] or any(sha_missing(ref,deadline or time.monotonic()+2) for ref in row['refs'])
    return row

def generation_key(value):
    # Numeric git commit time, optionally followed by its SHA, avoids lexical 9>10.
    if type(value) is int and 0 <= value < 10**20: return (value,'')
    if isinstance(value,str):
        match=re.fullmatch(r'(\d{1,20})(?::([0-9a-f]{7,64}))?',value)
        if match: return (int(match[1]),match[2] or '')
    fail('generation must be a nonnegative commit timestamp or timestamp:sha')

def sync(db,b,actor):
    surface=text_field(b.get('surface'),'surface',200,False)
    source=text_field(b.get('sync_source'),'sync_source',4096,False)
    sha=b.get('sha')
    if sha is not None and (not isinstance(sha,str) or not re.fullmatch(r'[0-9a-f]{7,64}',sha)): fail('invalid sha')
    generation=b.get('generation')
    key=generation_key(generation)
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
            upsert(db,item,actor,origin='manifest',validate_only=True)
            ordered.append(item); pending.remove(item)
    for item in ordered:
        aid=upsert(db,item,actor,origin='manifest')
        db.execute('UPDATE artifact SET last_verified=now(),last_synced=now() WHERE id=%s',(aid,))
    retired=db.execute("UPDATE artifact SET status='retired',updated_at=now() WHERE surface=%s AND sync_source=%s AND status='active' AND NOT(id=ANY(%s::text[])) RETURNING id",(surface,source,ids)).fetchall()
    db.execute('INSERT INTO sync_state(surface,sync_source,generation,sha) VALUES(%s,%s,%s,%s) ON CONFLICT(surface,sync_source) DO UPDATE SET generation=EXCLUDED.generation,sha=EXCLUDED.sha,at=now()',(surface,source,str(generation),sha))
    audit(db,actor,'sync',detail={'count':len(ids),'retired':len(retired)})
    return {'ids':['a#'+i for i in ids],'retired':['a#'+r['id'] for r in retired]}

class Handler(BaseHTTPRequestHandler):
    server_version='ArtifactRegistry/1'
    def log_message(self,*args): pass
    def reply(self,status,data):
        raw=json.dumps(data,default=lambda x:x.isoformat(),ensure_ascii=False).encode()
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(raw)
    def do_GET(self): self.handle_api()
    def do_POST(self): self.handle_api()
    def do_PUT(self): self.handle_api()
    def handle_api(self):
        status=500; actor=None
        try:
            self.connection.settimeout(15)
            parsed=urlsplit(self.path); path=parsed.path
            self.sha_deadline=time.monotonic()+2
            if self.command=='GET' and path=='/healthz':
                status=200; self.reply(200,{'ok':True}); return
            with psycopg.connect(self.server.dsn,row_factory=dict_row) as db:
                auth=self.headers.get('Authorization','')
                if not auth.startswith('Bearer ') or len(auth)>512: fail('bearer token required',401)
                digest=hashlib.sha256(auth[7:].encode()).hexdigest()
                token=None
                for row in db.execute('SELECT name,hash,scopes FROM token'):
                    if hmac.compare_digest(digest,row['hash']): token=row
                if not token: fail('invalid bearer token',401)
                actor=token['name']
                scope='dict' if path=='/v1/dictionary' else ('read' if self.command=='GET' else 'write')
                if scope not in token['scopes']: fail('insufficient scope: '+scope,403)
                body={}
                if self.command!='GET':
                    if self.headers.get('Transfer-Encoding'): fail('transfer encoding not supported',400)
                    try: length=int(self.headers.get('Content-Length','0'))
                    except ValueError: fail('invalid content length',400)
                    if length<0 or length>MAX_BODY: fail('body exceeds 256 KB',413)
                    try: body=json.loads(self.rfile.read(length))
                    except (ValueError,UnicodeError): fail('invalid JSON body',400)
                    if not isinstance(body,dict): fail('JSON body must be an object')
                    db.execute('SELECT pg_advisory_xact_lock(734927100)')
                result=self.dispatch(db,path,parse_qs(parsed.query),body,actor)
            status=200; self.reply(status,result)
        except APIError as e:
            status=e.status; self.close_connection=True; self.reply(status,{'error':e.message})
        except psycopg.IntegrityError as e:
            alias_error='alias' in (e.diag.constraint_name or '') or e.diag.message_primary=='alias_taken'
            status=409; self.close_connection=True; self.reply(status,{'error':'alias_taken' if alias_error else 'constraint conflict (parent or alias)'} )
        except (psycopg.Error,OSError):
            status=503; self.close_connection=True; self.reply(status,{'error':'registry unavailable'})
        except Exception:
            status=500; self.close_connection=True; self.reply(status,{'error':'internal registry error'})
        finally:
            # Deliberately no query strings, raw paths, request values or bodies.
            print(json.dumps({'method':self.command,'status':status,'actor':actor}),flush=True)
    def dispatch(self,db,path,q,b,actor):
        get=lambda key,default='':q.get(key,[default])[0]
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
                filters=["status='active'"]; vals=[]
                for key in ('surface','kind'):
                    if get(key): filters.append(key+'=%s'); vals.append(get(key))
                if path.endswith('search'):
                    term=text_field(get('q'),'q',500)
                    filters.append('(search @@ plainto_tsquery(\'simple\',%s) OR title %% %s OR title ILIKE %s)')
                    vals += [term,term,'%'+term.replace('\\','\\\\').replace('%',r'\%').replace('_',r'\_')+'%']
                vals.append(limit)
                rows=db.execute('SELECT * FROM artifact WHERE '+' AND '.join(filters)+' ORDER BY updated_at DESC,id LIMIT %s',vals).fetchall()
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
            return {'ids':['a#'+allocate(db,surface,actor) for _ in range(count)]}
        if (self.command=='POST' and path=='/v1/artifacts') or (self.command=='PUT' and path.startswith('/v1/artifacts/')):
            if self.command=='PUT':
                aid=id_value(path.removeprefix('/v1/artifacts/'))
                if b.get('id') and id_value(b['id'])!=aid: fail('path/body id mismatch')
                b['id']=aid
            aid=upsert(db,b,actor)
            return {'id':'a#'+aid}
        if self.command=='POST' and path=='/v1/sync':
            return sync(db,b,actor)
        if self.command=='POST' and path=='/v1/dictionary':
            term=text_field(b.get('term'),'term',200,False); guard(term)
            replacements=b.get('replace_from',[])
            if not isinstance(replacements,list) or len(replacements)>40: fail('invalid replace_from')
            for replacement in replacements: text_field(replacement,'replace_from',200,False); guard(replacement)
            source=b.get('source','manual')
            if not isinstance(source,str) or source not in {'wispr','harvest','learned','manual'}: fail('invalid dictionary source')
            db.execute('INSERT INTO dictionary(term,replace_from,source) VALUES(%s,%s,%s) ON CONFLICT(term) DO UPDATE SET replace_from=(SELECT ARRAY(SELECT DISTINCT unnest(dictionary.replace_from || EXCLUDED.replace_from))),source=EXCLUDED.source',(term,replacements,source))
            audit(db,actor,'dictionary')
            return {'term':term}
        fail('endpoint not found',404)

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,dsn):
        self.dsn=dsn
        super().__init__(address,Handler)

def main():
    Server((os.getenv('ARTIFACTS_BIND','0.0.0.0'),int(os.getenv('PORT','8080'))),os.environ['ARTIFACTS_DATABASE_URL']).serve_forever()
if __name__=='__main__': main()
