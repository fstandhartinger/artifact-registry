"""Dependency-free CLI/client shared by artifact and the stdio MCP adapter."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from artifact_ids import find_ids, normalise


def config():
    values={}
    path=Path.home()/'.config/dev-secrets.env'
    if path.exists():
        for line in path.read_text().splitlines():
            match=re.match(r'^(?:export\s+)?(ARTIFACTS_[A-Z_]+)=(.*)$',line)
            if match:
                try:
                    parts=shlex.split(match[2],comments=True)
                    if len(parts)==1: values[match[1]]=parts[0]
                except ValueError: pass
    # Never source shell code; caller's explicit environment always wins.
    values.update({k:v for k,v in os.environ.items() if k.startswith('ARTIFACTS_')})
    return values

class RegistryHTTPError(ValueError):
    def __init__(self,status,message):
        self.status=status
        super().__init__(f'registry HTTP {status}: {message}')

class Client:
    def __init__(self):
        values=config(); self.url=values.get('ARTIFACTS_URL','https://artifacts.app.mintapis.com').rstrip('/')
        self.token=values.get('ARTIFACTS_AGENT_TOKEN','')
        parsed=urllib.parse.urlsplit(self.url)
        if parsed.scheme not in {'https','http'} or (parsed.scheme=='http' and parsed.hostname not in {'localhost','127.0.0.1','::1'}):
            raise ValueError('registry URL requires HTTPS except on loopback')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('invalid registry URL')
    def request(self,path,body=None,method=None,**query):
        url=self.url+path
        if query: url+='?'+urllib.parse.urlencode({k:v for k,v in query.items() if v is not None})
        raw=None if body is None else json.dumps(body).encode()
        req=urllib.request.Request(url,data=raw,method=method or ('POST' if body is not None else 'GET'),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        # Do not follow redirects with bearer credentials.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs): return None
        try:
            with urllib.request.build_opener(NoRedirect).open(req,timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            try: message=json.load(e).get('error','request refused')
            except (ValueError,AttributeError): message='request refused'
            raise RegistryHTTPError(e.code,message) from None
        except (urllib.error.URLError,TimeoutError):
            raise ValueError('registry unavailable') from None
    def resolve(self,ids,expand=False,depth=1):
        result=self.request('/v1/resolve',ids=','.join(ids),depth=depth)
        if expand:
            for item in result['items']:
                item['expanded_refs']=[{'ref':r,'text':expand_ref(r,item.get('access'))} for r in item.get('refs',[])]
        return result
    def search(self,q,surface=None): return self.request('/v1/search',q=q,surface=surface)
    def list(self,surface): return self.request('/v1/list',surface=surface)
    def upsert(self,item): return self.request('/v1/artifacts',item)


def redact(text):
    text=re.sub(r'(?i)(?:\b(?:sk|ghp|github_pat|gho|xox[baprs])[-_][a-z0-9_-]{8,}|\bAKIA[A-Z0-9]{16}|\bbearer\s+[^\s"\']+|\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+|\b(?:password|passwd|api[_-]?key|[a-z_]*token|[a-z_]*secret|[a-z_]*database_url)\s*[:=]\s*[^\n,]+)', '[REDACTED]',text)
    text=re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)','[REDACTED PRIVATE KEY]',text,flags=re.S)
    return text[:12000]

def run_read(args):
    try:
        # Spool bounded command output rather than allowing unlimited capture in memory.
        import tempfile
        with tempfile.TemporaryFile() as output:
            proc=subprocess.run(args,stdout=output,stderr=subprocess.DEVNULL,timeout=10,check=False)
            output.seek(0); value=output.read(128*1024).decode(errors='replace')
        if proc.returncode: return '[reference unavailable]'
        return value
    except (OSError,subprocess.TimeoutExpired): return '[reference unavailable]'

def allowed_file(target,access):
    path=Path(target).expanduser().resolve()
    home=Path.home()
    roots=[home/'jobs',home/'work',home/'.agents/skills']
    if access=='private': roots.append(home/'finance')
    allowed=path==home/'AGENTS.md' or any(path.is_relative_to(root.resolve()) for root in roots)
    # Block credential-bearing paths even if a job directory references them.
    if not allowed or any(p in {'.env','dev-secrets.env','secrets-backups','.git','.ssh','.notify'} or p.startswith('.env.') or p.endswith(('.pem','.key')) for p in path.parts):
        raise ValueError('file reference is outside allowed roots or is a credential file')
    if not path.is_file(): raise ValueError('file reference unavailable')
    return path

def read_lines(path,start=1,end=80):
    if start<1 or end<start: raise ValueError('invalid line range')
    lines=[]
    with path.open(errors='replace') as handle:
        for n,line in enumerate(handle,1):
            if n<start: continue
            if n>min(end,start+79): break
            lines.append(line[:2000])
    return ''.join(lines)

def expand_ref(ref,access='private'):
    kind,target=ref['kind'],ref['target']
    try:
        if kind in {'file','readme','doc'}:
            match=re.fullmatch(r'(.+?)(?:#L(\d+)(?:-L?(\d+))?)?',target)
            start=int(match[2] or 1); end=int(match[3] or (start+79))
            value=read_lines(allowed_file(match[1],access),start,end)
        elif kind=='code':
            match=re.fullmatch(r'github:([\w.-]+)/([\w.-]+)@([\w./-]+):([^#]+)(?:#L(\d+)(?:-L?(\d+))?)?',target)
            if not match: return '[invalid code reference]'
            owner,repo,rev,path,start,end=match.groups()
            if owner in {'.','..'} or repo in {'.','..'}: return '[invalid code repository]'
            rev=ref.get('pinned_sha') or rev
            endpoint='repos/'+owner+'/'+repo+'/contents/'+urllib.parse.quote(path,safe='/')+'?ref='+urllib.parse.quote(rev,safe='')
            response=json.loads(run_read(['gh','api',endpoint]))
            if response.get('size',0)>1024*1024: return '[code file exceeds 1 MB]'
            if response.get('encoding')!='base64': return '[code content unavailable]'
            lines=base64.b64decode(response['content']).decode(errors='replace').splitlines()
            lo=max(1,int(start or 1)); hi=min(int(end or lo+79),lo+79)
            value='\n'.join(lines[lo-1:hi])
        elif kind=='board':
            match=re.fullmatch(r'board(?:-thread)?:([0-9]+)',target)
            if not match: return '[invalid board reference]'
            value=run_read([str(Path.home()/'bin/agent-board'),'read',match[1]])
        elif kind=='decision':
            key=target.removeprefix('decisions:')
            if len(key)>200: return '[invalid decision key]'
            lines=(Path.home()/'DECISIONS.md').read_text().splitlines(); found=[]
            for n,line in enumerate(lines):
                if key in line:
                    found.extend(lines[max(0,n-3):n+9])
                    if len(found)>=80: break
            value='\n'.join(found[:80])
        elif kind=='card':
            match=re.fullmatch(r'card:([0-9]+)',target)
            if not match: return '[invalid card reference]'
            value=read_lines(Path.home()/'.notify/cards'/f'{match[1]}.json')
        elif kind=='job':
            name=target.removeprefix('job:')
            if not re.fullmatch(r'[\w.-]+',name) or name in {'.','..'}: return '[invalid job reference]'
            folder=Path.home()/'jobs'/name
            path=folder/'RESULT.md' if (folder/'RESULT.md').exists() else folder/'STATE.md'
            value=read_lines(allowed_file(str(path),access))
        elif kind=='artifact':
            value=json.dumps(Client().resolve([target]),ensure_ascii=False)
        else:
            return '[pointer: '+target+']'
        return redact('\n'.join(value.splitlines()[:80]))
    except (OSError,ValueError,KeyError,TypeError): return '[reference unavailable or refused]'


def import_dictionary(client,path,source='wispr'):
    count=0
    for line in Path(path).read_text().splitlines():
        line=line.strip()
        if not line or line.startswith('#'): continue
        if '@' in line: continue
        parts=re.split(r'\s*(?:->|→)\s*',line,maxsplit=1)
        term=parts[-1].strip(); before=[parts[0].strip()] if len(parts)==2 else []
        client.request('/v1/dictionary',{'term':term,'replace_from':before,'source':source}); count+=1
    return {'imported':count}

def stamp(path,aid):
    label='a#'+normalise(aid)
    try:
        from PIL import Image,ImageDraw,ImageFont
    except ImportError:
        # ImageMagick defaults preserve the input and write a sibling output too.
        output=Path(path).with_name(Path(path).stem+'.stamped.png')
        subprocess.run(['convert',str(path),'-gravity','NorthEast','-background','#18202BCC','-fill','#B7C0CE','-pointsize','14','-splice','0x28','-annotate','+10+6',label,str(output)],check=True)
        return str(output)
    image=Image.open(path).convert('RGBA'); overlay=Image.new('RGBA',image.size)
    draw=ImageDraw.Draw(overlay)
    try: font=ImageFont.truetype('DejaVuSansMono.ttf',14)
    except OSError: font=ImageFont.load_default()
    box=draw.textbbox((0,0),label,font=font); width=box[2]-box[0]+16; height=26
    x=max(0,image.width-width-10); y=10
    draw.rounded_rectangle((x,y,x+width,y+height),radius=6,fill=(24,32,43,210))
    draw.text((x+8,y+3),label,font=font,fill=(183,192,206,255))
    output=Path(path).with_name(Path(path).stem+'.stamped.png')
    Image.alpha_composite(image,overlay).save(output)
    return str(output)

def pool_action(action, surface, client=None, root=None):
    import fcntl
    import tempfile
    root=Path(root) if root is not None else Path.home()/'.config/artifact-ids'
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not isinstance(surface,str) or not surface or len(surface)>200: raise ValueError('invalid surface')
    path=root/('pool-'+urllib.parse.quote(surface,safe='')+'.json')
    lock=os.open(str(path)+'.lock',os.O_CREAT|os.O_RDWR,0o600)
    try:
        os.fchmod(lock,0o600)
        fcntl.flock(lock,fcntl.LOCK_EX)
        ids=json.loads(path.read_text()) if path.exists() else []
        if not isinstance(ids,list) or len(ids)>200: raise ValueError('invalid pool')
        ids=[normalise(i) for i in ids]
        if len(set(ids))!=len(ids): raise ValueError('duplicate ids in pool')
        if action=='refill':
            if len(ids)<50:
                more=(client or Client()).request('/v1/ids',{'surface':surface,'count':200-len(ids)})['ids']
                ids.extend(normalise(i) for i in more)
                if len(ids)!=200 or len(set(ids))!=200: raise ValueError('invalid allocation response')
            result={'count':len(ids)}
        elif action=='take':
            if not ids: raise ValueError('pool empty; refill online first')
            result={'id':'a#'+ids.pop(0)}
        else: raise ValueError('unknown pool action')
        fd,tmp=tempfile.mkstemp(prefix=path.name+'.',dir=root)
        try:
            with os.fdopen(fd,'w') as handle:
                json.dump(ids,handle); handle.flush(); os.fsync(handle.fileno())
            os.replace(tmp,path)
            directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
        return result
    finally: os.close(lock)

def check_code_ref(ref, repos):
    match=re.fullmatch(r'github:([\w.-]+/[\w.-]+)@([^:]+):([^#]+)(?:#.*)?',ref['target'])
    if not match: return 'invalid code reference'
    repo,rev,path=match.groups(); pinned=ref.get('pinned_sha') or rev
    if any(part in {'.','..'} for part in repo.split('/')): return 'invalid code repository'
    if not re.fullmatch(r'[0-9a-f]{7,64}',pinned): return 'code ref lacks pinned sha'
    if path.startswith('/') or '..' in Path(path).parts: return 'invalid code path'
    for version,label in [(pinned,'pinned sha'),('HEAD','HEAD')]:
        if repo in repos:
            args=['git','-C',str(repos[repo]),'cat-file','-e',version+':'+path]
        else:
            args=['gh','api','repos/'+repo+'/contents/'+urllib.parse.quote(path,safe='/')+'?ref='+version,'--silent']
        try:
            result=subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            if result.returncode: return 'code path missing or unavailable at '+label
        except (OSError,subprocess.TimeoutExpired): return 'code ref verification unavailable'
    return None

def verify_refs(client, repos=None):
    after=''; checked=0; stale=0; conflicts=0
    while True:
        rows=client.request('/v1/verify-refs',after=after)['items']
        if not rows: break
        for row in rows:
            reasons=sorted(set(filter(None,(check_code_ref(ref,repos or {}) for ref in row['refs']))))
            reason='; '.join(reasons) or None
            try:
                client.request('/v1/verify-refs',{'id':row['id'],'refs':row['refs'],'stale_reason':reason})
            except RegistryHTTPError as error:
                if error.status != 409: raise
                conflicts+=1
                continue
            checked+=1; stale+=bool(reason)
        after=normalise(rows[-1]['id'])
    return {'checked':checked,'stale':stale,'conflicts':conflicts}

def sync_manifest(path,generation=None):
    path=Path(path).resolve()
    payload=json.loads(path.read_text())
    return sync_payload(payload,generation,path.parent)

def sync_payload(payload,generation=None,git_dir=None):
    if not isinstance(payload,dict): raise ValueError('sync manifest must be an object')
    payload=dict(payload)
    # Preserve items arrays and component-keyed objects; server validates their rows.
    if generation is not None:
        payload['generation']=generation
    elif 'generation' not in payload:
        try:
            result=subprocess.run(['git','-C',str(git_dir or Path.cwd()),'log','-1','--format=%ct:%H'],
                                  capture_output=True,text=True,timeout=10,check=True)
            value=result.stdout.strip()
            if not re.fullmatch(r'\d+:[0-9a-f]{7,64}',value): raise ValueError('invalid git generation')
            payload['generation']=value
        except (OSError,subprocess.SubprocessError,ValueError):
            payload['generation']=int(time.time())
    return payload

def main(argv=None):
    parser=argparse.ArgumentParser(description='Resolve and register artifact pointers')
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('resolve'); p.add_argument('ids',nargs='+'); p.add_argument('--expand',action='store_true'); p.add_argument('--json',action='store_true'); p.add_argument('--depth',type=int,choices=[0,1,2],default=1)
    p=sub.add_parser('search'); p.add_argument('q'); p.add_argument('--surface')
    p=sub.add_parser('list'); p.add_argument('--surface',required=True)
    p=sub.add_parser('new')
    p.add_argument('--kind',required=True); p.add_argument('--title',required=True); p.add_argument('--surface',required=True)
    for name in ('summary','parent','url','selector','owner-job','access'): p.add_argument('--'+name)
    p.add_argument('--ref',action='append',default=[]); p.add_argument('--alias',action='append',default=[])
    p=sub.add_parser('add-ref'); p.add_argument('id'); p.add_argument('ref',help='kind=target'); p.add_argument('--label')
    p=sub.add_parser('sync'); p.add_argument('manifest'); p.add_argument('--generation')
    p=sub.add_parser('scan'); p.add_argument('input',nargs='+')
    p=sub.add_parser('stamp'); p.add_argument('png'); p.add_argument('--id',required=True)
    p=sub.add_parser('dict'); ds=p.add_subparsers(dest='action',required=True)
    ds.add_parser('list')
    p=ds.add_parser('add'); p.add_argument('term'); p.add_argument('--from',dest='replace_from',action='append',default=[]); p.add_argument('--source',default='manual')
    p=ds.add_parser('import'); p.add_argument('file'); p.add_argument('--source',default='wispr')
    p=sub.add_parser('pool'); ps=p.add_subparsers(dest='action',required=True)
    for action in ('refill','take'):
        pp=ps.add_parser(action); pp.add_argument('--surface',required=True)
    p=sub.add_parser('link'); p.add_argument('src'); p.add_argument('rel'); p.add_argument('dst')
    p=sub.add_parser('verify-refs'); p.add_argument('--repo',action='append',default=[],metavar='OWNER/REPO=PATH')
    args=parser.parse_args(argv)
    try:
        if args.command=='pool':
            print(json.dumps(pool_action(args.action,args.surface))); return 0
        client=Client()
        if args.command=='resolve': result=client.resolve(args.ids,args.expand,args.depth)
        elif args.command=='link':
            rows=client.resolve([args.src],depth=0)['items']
            if not rows: raise ValueError('source artifact not found')
            result=client.upsert({'id':rows[0]['id'],'links':[{'rel':args.rel,'to':args.dst}]})
        elif args.command=='verify-refs': result=verify_refs(client,dict(r.split('=',1) for r in args.repo))
        elif args.command=='search': result=client.search(args.q,args.surface)
        elif args.command=='list': result=client.list(args.surface)
        elif args.command=='new':
            item={k:v for k,v in vars(args).items() if k in {'kind','title','surface','summary','parent','url','selector','owner_job','access'} and v is not None}
            item['refs']=[dict(zip(('kind','target'),r.split('=',1))) for r in args.ref]
            item['aliases']=args.alias; result=client.upsert(item)
            print(result['id']); return 0
        elif args.command=='add-ref':
            item=client.resolve([args.id])['items']
            if not item: raise ValueError('artifact not found')
            row=item[0]; kind,target=args.ref.split('=',1)
            refs=[{k:v for k,v in r.items() if k!='ord'} for r in row['refs'] if r.get('origin','agent')=='agent']
            refs.append({'kind':kind,'target':target,'label':args.label})
            result=client.upsert({'id':row['id'],'refs':refs})
        elif args.command=='sync': result=client.request('/v1/sync',sync_manifest(args.manifest,args.generation))
        elif args.command=='scan':
            texts=[]
            for value in args.input:
                try: is_file=len(value)<4096 and Path(value).is_file()
                except OSError: is_file=False
                texts.append(Path(value).read_text() if is_file else value)
            ids=find_ids('\n'.join(texts)); known=[]
            for n in range(0,len(ids),100): known.extend(client.request('/v1/exists',ids=','.join(ids[n:n+100]))['known'])
            result={'known':known}
        elif args.command=='stamp': result={'file':stamp(args.png,args.id)}
        elif args.command=='dict':
            if args.action=='list': result=client.request('/v1/dictionary')
            elif args.action=='add': result=client.request('/v1/dictionary',{'term':args.term,'replace_from':args.replace_from,'source':args.source})
            else: result=import_dictionary(client,args.file,args.source)
        print(json.dumps(result,indent=2,ensure_ascii=False)); return 0
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print(str(e),file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
