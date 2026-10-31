"""Fetch immutable GitHub manifests and use the artifact CLI sync payload path."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

from artifact_cli import Client, RegistryHTTPError, sync_payload


def gh_api(endpoint, raw=False):
    args=['gh','api',endpoint]
    if raw: args += ['-H','Accept: application/vnd.github.raw+json']
    result=subprocess.run(args, capture_output=True, text=True, timeout=45)
    if result.returncode:
        # Never log gh stderr: it may include private payloads or auth details.
        raise ValueError('GitHub fetch failed')
    return json.loads(result.stdout)


def fetch_manifest(source):
    repo=source['repo']; path=source['path']; branch=source['branch']
    if not re.fullmatch(r'[\w.-]+/[\w.-]+',repo) or any(p in {'.','..'} for p in repo.split('/')):
        raise ValueError('invalid repository')
    if not isinstance(path,str) or not path or any(p in {'','..','.'} for p in path.split('/')):
        raise ValueError('invalid manifest path')
    if not isinstance(branch,str) or not branch: raise ValueError('invalid branch')
    commit=gh_api(f'repos/{repo}/commits/{quote(branch,safe="")}')
    sha=commit['sha']
    if not re.fullmatch(r'[0-9a-f]{40,64}',sha): raise ValueError('invalid commit sha')
    timestamp=int(datetime.fromisoformat(commit['commit']['committer']['date'].replace('Z','+00:00')).timestamp())
    payload=gh_api(f'repos/{repo}/contents/{quote(path,safe="/")}?ref={sha}',raw=True)
    if not isinstance(payload,dict): raise ValueError('invalid manifest')
    if 'items' not in payload:
        if not source.get('surface'): raise ValueError('legacy manifest requires surface')
        payload={'surface':source['surface'],'items':payload}
    if source.get('surface') and payload.get('surface')!=source['surface']:
        raise ValueError('surface mismatch')
    items=payload['items']
    if not isinstance(items,(dict,list)): raise ValueError('invalid items')
    normalized={}
    for key,item in (items.items() if isinstance(items,dict) else enumerate(items)):
        if not isinstance(item,dict): raise ValueError('invalid item')
        item=dict(item)
        for field in ('url','owner_job','access'):
            if field in source: item.setdefault(field,source[field])
        if source.get('alias_prefix'):
            if not isinstance(items,dict): raise ValueError('alias prefix requires keyed items')
            item['aliases']=list(dict.fromkeys([*item.get('aliases',[]),source['alias_prefix']+key]))
        normalized[key]=item
    payload=dict(payload,items=normalized,sha=sha,
                 sync_source=f'github:{repo}/{path}')
    return sync_payload(payload,f'{timestamp}:{sha}')


def run(sources_path, log_path, client=None):
    sources=json.loads(Path(sources_path).read_text())
    if not isinstance(sources,list): raise ValueError('sources must be a list')
    log_path=Path(log_path); log_path.parent.mkdir(parents=True,exist_ok=True)
    errors=0
    client=client or Client()
    for source in sources:
        # JSON encoding keeps every entry on one line, even with malformed config.
        label={k:source.get(k) for k in ('repo','path','branch')} if isinstance(source,dict) else {}
        try:
            payload=fetch_manifest(source)
            try:
                client.request('/v1/sync',payload)
                status='synced'
            except RegistryHTTPError as error:
                if error.status==409 and str(error)=='registry HTTP 409: stale_generation': status='no change'
                else: raise
        except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError) as error:
            errors+=1; status='error'
            # Only the exception class and a registry status/code; never manifest or API response bodies.
            reason=type(error).__name__
            if isinstance(error,RegistryHTTPError): reason=str(error)[:80]
        else:
            reason=None
        line=json.dumps(dict(at=datetime.now(timezone.utc).isoformat(),**label,status=status,**({'reason':reason} if reason else {})),ensure_ascii=True)
        with log_path.open('a') as handle: handle.write(line+'\n')
        print(line)
    return 1 if errors else 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources',default=Path.home()/'.config/artifact-sync/sources.json')
    parser.add_argument('--log',default=Path.home()/'.local/state/artifact-sync/log')
    args=parser.parse_args()
    try: return run(args.sources,args.log)
    except (ValueError,OSError):
        print('artifact-sync-all: configuration or registry initialization failed')
        return 1
