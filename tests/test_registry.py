import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request

import psycopg
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from artifact_cli import config, Client, allowed_file, expand_ref, redact
from artifact_ids import normalise,find_ids,new_id
from registry import Server

class RegistryTests(unittest.TestCase):
    @classmethod
    def admin(cls,query):
        result=subprocess.run(['sudo','-n','-u','postgres','psql','-X','-qAt','-v','ON_ERROR_STOP=1'],input=query,text=True,capture_output=True)
        if result.returncode: raise RuntimeError('test database admin failed')
        return result.stdout.strip()
    @classmethod
    def setUpClass(cls):
        if cls.admin("SELECT 1 FROM pg_database WHERE datname='artifacts_test'"):
            raise RuntimeError('artifacts_test already exists; refusing to use or drop an unowned database')
        cls.admin('CREATE DATABASE artifacts_test OWNER artifacts_app')
        cls.dsn=config()['ARTIFACTS_DATABASE_URL'].rsplit('/',1)[0]+'/artifacts_test'
        with psycopg.connect(cls.dsn) as db:
            migration=(Path(__file__).resolve().parents[1]/'migrations/001_init.sql').read_text()
            db.execute(migration); db.execute(migration) # idempotent
            for name,scopes in [('all',['read','write','dict']),('desk',['read','dict']),('writer',['write']),('reader',['read'])]:
                db.execute('INSERT INTO token(name,hash,scopes) VALUES(%s,%s,%s)',(name,hashlib.sha256(('test-'+name).encode()).hexdigest(),scopes))
        cls.server=Server(('127.0.0.1',0),cls.dsn)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
        cls.admin('DROP DATABASE artifacts_test')
    def setUp(self):
        self.sha_patch=patch('registry.sha_missing',return_value=False)
        self.sha_patch.start(); self.addCleanup(self.sha_patch.stop)
        with psycopg.connect(self.dsn) as db:
            db.execute('TRUNCATE artifact,artifact_alias,artifact_ref,audit,dictionary CASCADE')
    def request(self,path,body=None,token='all',method=None,raw=None):
        headers={'Content-Type':'application/json'}
        if token is not None: headers['Authorization']='Bearer test-'+token
        data=raw if raw is not None else (None if body is None else json.dumps(body).encode())
        req=urllib.request.Request(self.base+path,data=data,method=method,headers=headers)
        try:
            with urllib.request.urlopen(req,timeout=5) as res: return res.status,json.load(res)
        except urllib.error.HTTPError as e: return e.code,json.load(e)
    def get_ids(self,endpoint,ids):
        return self.request('/v1/'+endpoint+'?'+urllib.parse.urlencode({'ids':ids}))
    def create(self,aid='abc123',**extra):
        data={'id':aid,'kind':'panel','title':'Reserve projection','surface':'test','summary':'Shows reserve assumptions.'}
        data.update(extra); return self.request('/v1/artifacts',data)
    def test_health_and_auth(self):
        self.assertEqual(self.request('/healthz',token=None),(200,{'ok':True}))
        self.assertEqual(self.request('/v1/list',token=None)[0],401)
        self.assertEqual(self.request('/v1/list',token='bad')[0],401)
        self.assertEqual(self.request('/v1/artifacts',{},token='desk')[0],403)
        self.assertEqual(self.request('/v1/dictionary',token='reader')[0],403)
        self.assertEqual(self.request('/v1/list',token='writer')[0],403)
        self.assertEqual(self.request('/v1/dictionary',{'term':'Jev'},token='desk')[0],200)
    def test_upsert_alias_exists_and_graph(self):
        self.assertEqual(self.create('AbC123',aliases=['card:18557'])[1]['id'],'a#abc123')
        self.assertEqual(self.create('bbccdd',parent='A#ABC123',title='Child')[0],200)
        self.assertEqual(self.get_ids('exists','a#ABC123,ffffff,card:18557')[1],{'known':['a#abc123']})
        result=self.get_ids('resolve','card:18557,18557,A#BBCCDD,ffffff')[1]
        self.assertEqual(result['unknown'],['ffffff'])
        self.assertEqual(result['items'][0]['children'][0]['id'],'a#bbccdd')
        self.assertEqual(result['items'][2]['parent']['id'],'a#abc123')
        self.assertEqual(self.request('/v1/artifacts/abc123',{'title':'Updated'},method='PUT')[0],200)
        self.assertEqual(self.get_ids('resolve','abc123')[1]['items'][0]['aliases'],['card:18557'])
    def test_refs_replace_and_owner(self):
        self.create(refs=[{'kind':'repo','target':'github:example/registry'}],aliases=['card:1'])
        self.assertEqual(self.create(surface='other')[0],409)
        self.assertEqual(self.create('bbccdd',aliases=['card:1'])[0],409)
        self.assertEqual(self.create(refs=[],aliases=[])[0],200)
        result=self.get_ids('resolve','abc123')[1]['items'][0]
        self.assertEqual(result['refs'],[]); self.assertEqual(result['aliases'],[])
    def test_generated_reserved_ids(self):
        status,result=self.request('/v1/ids',{'count':3,'surface':'test'})
        self.assertEqual(status,200); self.assertEqual(len(set(result['ids'])),3)
        self.assertEqual(self.get_ids('exists',','.join(result['ids']))[1],{'known':[]})
        self.assertEqual(self.create(result['ids'][0])[0],200)
        status,row=self.request('/v1/artifacts',{'kind':'app','title':'Registry','surface':'test'})
        self.assertEqual(status,200); self.assertRegex(row['id'],r'^a#[0-9a-f]{6}$')
    def test_sync_retirement_pins_and_rollback(self):
        self.create('111111'); self.create('222222',surface='other')
        manifest={'surface':'test','sync_source':'manifest example','sha':'a'*40,'items':[
            {'id':'aabbcc','kind':'panel','title':'Child','parent':'ddeeff','refs':[{'kind':'code','target':'github:example/app@HEAD:src/app.py#L1-L4'}]},
            {'id':'ddeeff','kind':'page','title':'Page'}]}
        status,result=self.request('/v1/sync',manifest)
        self.assertEqual(status,200); self.assertEqual(result['retired'],['a#111111'])
        row=self.get_ids('resolve','aabbcc')[1]['items'][0]
        self.assertFalse(row['stale']); self.assertIn('@'+'a'*40+':',row['refs'][0]['target'])
        self.assertEqual(row['refs'][0]['pinned_sha'],'a'*40)
        self.assertEqual(len(self.request('/v1/list?surface=other')[1]['items']),1)
        manifest['items'][0]['title']='password=hunter22'
        self.assertEqual(self.request('/v1/sync',manifest)[0],422)
        self.assertEqual(self.get_ids('resolve','aabbcc')[1]['items'][0]['title'],'Child')
        self.assertEqual(self.request('/v1/sync',{'surface':'test','sync_source':'manifest','items':[]})[0],200)
        self.assertEqual(self.request('/v1/list?surface=test')[1]['items'],[])
    def test_guards(self):
        for value in ['sk-abcdefghijklmnop','Bearer testsecret','eyJabc.abc.def','-----BEGIN PRIVATE KEY-----','seed phrase here','DE89 3704 0044 0532 0130 00','password=hunter2','api_key=examplekey','abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about']:
            with self.subTest(value=value): self.assertEqual(self.create(title=value)[0],422)
        for value in ['EUR 123','€ 1,234','123 TAO','α 123','123 EUR']:
            self.assertEqual(self.create(title=value,surface='app:bittensor-earnings/reax')[0],422)
            self.assertEqual(self.create(title=value,kind='finance')[0],422)
        self.assertEqual(self.create(title='36 months projection',surface='app:bittensor-earnings')[0],200)
        self.assertEqual(self.create(title='EUR 12',surface='app:bittensor-earnings')[0],200)
        self.assertEqual(self.create('abc124',refs=[{'kind':'endpoint','target':'https://example.com?token=private'}])[0],422)
    def test_validation(self):
        for extra in [{'title':'x'*201},{'summary':'x'*1201},{'refs':[{}]*41},{'id':'wrong'},{'aliases':['abcdef']},{'parent':'abc123'},{'status':[]},{'access':{}},{'refs':[{'kind':[],'target':'test'}]}]:
            self.assertEqual(self.create(**extra)[0],422)
        self.assertEqual(self.request('/v1/artifacts',raw=b'{')[0],400)
        self.assertEqual(self.request('/v1/artifacts',raw=b' '*262145)[0],413)
        self.assertEqual(self.request('/v1/search?limit=NaN')[0],422)
    def test_parent_cycle(self):
        self.create('111111'); self.create('222222',parent='111111')
        self.assertEqual(self.create('111111',parent='222222')[0],422)
    def test_search_dictionary_and_audit(self):
        self.create()
        self.assertEqual(len(self.request('/v1/search?q=projection')[1]['items']),1)
        self.assertEqual(len(self.request('/v1/search?q=projecton')[1]['items']),1)
        self.request('/v1/dictionary',{'term':'Jev','replace_from':['Jeff'],'source':'wispr'})
        self.request('/v1/dictionary',{'term':'Jev','replace_from':['Jef'],'source':'learned'})
        self.assertEqual(set(self.request('/v1/dictionary')[1]['items'][0]['replace_from']),{'Jeff','Jef'})
        with psycopg.connect(self.dsn) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0],3)
    def test_sha_check_budget_and_cache(self):
        import time
        import registry
        from unittest.mock import MagicMock
        ref={'kind':'code','target':'github:example/app@'+'b'*40+':main.py'}
        registry._SHA_CACHE.clear()
        self.sha_patch.stop()
        try:
            self.assertTrue(registry.sha_missing(ref,time.monotonic()-1))
            opener=MagicMock()
            opener.open.return_value.__enter__.return_value.status=200
            with patch('registry.urllib.request.build_opener',return_value=opener):
                self.assertFalse(registry.sha_missing(ref,time.monotonic()+2))
                self.assertFalse(registry.sha_missing(ref,time.monotonic()+2))
                self.assertEqual(opener.open.call_count,1)
        finally:
            registry._SHA_CACHE.clear()
            self.sha_patch.start()

    def test_sha_freshness(self):
        self.create(refs=[{'kind':'code','target':'github:example/app@'+'a'*40+':main.py'}])
        self.assertFalse(self.get_ids('resolve','abc123')[1]['items'][0]['stale'])
        with patch('registry.sha_missing',return_value=True):
            self.assertTrue(self.get_ids('resolve','abc123')[1]['items'][0]['stale'])

    def test_mcp_scripted(self):
        import os
        self.create()
        requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'test','version':'1'}}},
                  {'jsonrpc':'2.0','method':'notifications/initialized'},
                  {'jsonrpc':'2.0','id':2,'method':'tools/list'},
                  {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'artifact_resolve','arguments':{'ids':['A#abc123']}}},
                  {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'artifact_search','arguments':{'q':'projection'}}},
                  {'jsonrpc':'2.0','id':5,'method':'tools/call','params':{'name':'artifact_list','arguments':{'surface':'test'}}},
                  {'jsonrpc':'2.0','id':6,'method':'tools/call','params':{'name':'artifact_upsert','arguments':{'id':'abc124','kind':'doc','title':'Created by MCP','surface':'test'}}},
                  {'jsonrpc':'2.0','id':7,'method':'tools/call','params':{'name':'artifact_resolve','arguments':{'ids':'invalid'}}}]
        env=dict(os.environ,ARTIFACTS_URL=self.base,ARTIFACTS_AGENT_TOKEN='test-all')
        result=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'bin/artifact-mcp')],input='\n'.join(map(json.dumps,requests))+'\n',text=True,capture_output=True,env=env,check=True)
        replies=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(replies),7)
        self.assertEqual(replies[0]['result']['protocolVersion'],'2025-06-18')
        self.assertEqual(len(replies[1]['result']['tools']),4)
        self.assertEqual(json.loads(replies[2]['result']['content'][0]['text'])['items'][0]['id'],'a#abc123')
        self.assertFalse(any(row['result'].get('isError') for row in replies[2:6]))
        self.assertTrue(replies[6]['result']['isError'])
        self.assertEqual(result.stderr,'')

if __name__=='__main__': unittest.main()
