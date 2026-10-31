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
from artifact_ids import normalise,find_ids
from registry import Server

class RegistryTests(unittest.TestCase):
    @classmethod
    def admin(cls,query):
        result=subprocess.run(['sudo','-n','-u','postgres','psql','-X','-qAt','-v','ON_ERROR_STOP=1'],input=query,text=True,capture_output=True)
        if result.returncode: raise RuntimeError('test database admin failed')
        return result.stdout.strip()
    @classmethod
    def setUpClass(cls):
        if cls.admin("SELECT 1 FROM pg_database WHERE datname='artifacts_v2test'"):
            raise RuntimeError('artifacts_v2test already exists; refusing to use or drop an unowned database')
        cls.admin('CREATE DATABASE artifacts_v2test OWNER artifacts_app')
        cls.dsn=config()['ARTIFACTS_DATABASE_URL'].rsplit('/',1)[0]+'/artifacts_v2test'
        with psycopg.connect(cls.dsn) as db:
            migration=(Path(__file__).resolve().parents[1]/'migrations/001_init.sql').read_text()
            db.execute(migration); db.execute(migration) # idempotent
            # Upgrade a populated copy of the v1 schema, twice, without touching live DB.
            db.execute("INSERT INTO artifact(id,kind,title,surface) VALUES('ffffff','doc','Existing','upgrade')")
            db.execute("INSERT INTO artifact_alias VALUES('card:999','ffffff')")
            db.execute("INSERT INTO artifact_ref(artifact_id,kind,target) VALUES('ffffff','file','/example')")
            migration2=(Path(__file__).resolve().parents[1]/'migrations/002_v2.sql').read_text()
            db.execute(migration2); db.execute(migration2)
            assert db.execute("SELECT title FROM artifact WHERE id='ffffff'").fetchone()[0]=='Existing'
            assert db.execute("SELECT origin FROM artifact_ref WHERE artifact_id='ffffff'").fetchone()[0]=='agent'
            assert db.execute("SELECT artifact_id FROM artifact_alias WHERE alias='card:999'").fetchone()[0]=='ffffff'
            for name,scopes in [('all',['read','write','dict','sync','timer','admin','devices']),('desk',['read','dict']),('writer',['write']),('reader',['read'])]:
                db.execute('INSERT INTO token(name,hash,scopes) VALUES(%s,%s,%s)',(name,hashlib.sha256(('test-'+name).encode()).hexdigest(),scopes))
            migration3=(Path(__file__).resolve().parents[1]/'migrations/003_devices.sql').read_text()
            db.execute(migration3); db.execute(migration3)
        cls.server=Server(('127.0.0.1',0),cls.dsn)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
        cls.admin('DROP DATABASE artifacts_v2test')
    def setUp(self):
        self.sha_patch=patch('registry.sha_missing',return_value=False)
        self.sha_patch.start(); self.addCleanup(self.sha_patch.stop)
        with psycopg.connect(self.dsn) as db:
            db.execute('TRUNCATE device,artifact,artifact_alias,artifact_ref,artifact_link,sync_state,audit,dictionary CASCADE')
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
    def reserve(self,*ids,surface='test'):
        with psycopg.connect(self.dsn) as db:
            for aid in ids:
                db.execute("INSERT INTO artifact(id,kind,title,surface,status) VALUES(%s,'element','',%s,'reserved') ON CONFLICT(id) DO UPDATE SET surface=EXCLUDED.surface WHERE artifact.status='reserved'",(normalise(aid),surface))
    def create(self,aid='abc123',**extra):
        try:
            self.reserve(extra.get('id',aid),surface=extra.get('surface','test'))
        except ValueError: pass
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
        self.assertEqual(result['refs'],[]); self.assertEqual(result['aliases'],['card:1'])
    def test_generated_reserved_ids(self):
        status,result=self.request('/v1/ids',{'count':3,'surface':'test'})
        self.assertEqual(status,200); self.assertEqual(len(set(result['ids'])),3)
        self.assertEqual(self.get_ids('exists',','.join(result['ids']))[1],{'known':[]})
        self.assertEqual(self.create(result['ids'][0])[0],200)
        status,row=self.request('/v1/artifacts',{'kind':'app','title':'Registry','surface':'test'})
        self.assertEqual(status,200); self.assertRegex(row['id'],r'^a#[0-9a-f]{6}$')
    def test_sync_retirement_pins_and_rollback(self):
        self.create('111111',sync_source='manifest example'); self.create('222222',surface='other')
        self.reserve('aabbcc','ddeeff')
        manifest={'generation':1,'surface':'test','sync_source':'manifest example','sha':'a'*40,'items':[
            {'id':'aabbcc','kind':'panel','title':'Child','parent':'ddeeff','refs':[{'kind':'code','target':'github:example/app@HEAD:src/app.py#L1-L4'}]},
            {'id':'ddeeff','kind':'page','title':'Page'}]}
        status,result=self.request('/v1/sync',manifest)
        self.assertEqual(status,200); self.assertEqual(result['retired'],['a#111111'])
        row=self.get_ids('resolve','aabbcc')[1]['items'][0]
        self.assertFalse(row['stale']); self.assertIn('@'+'a'*40+':',row['refs'][0]['target'])
        self.assertEqual(row['refs'][0]['pinned_sha'],'a'*40)
        self.assertEqual(len(self.request('/v1/list?surface=other')[1]['items']),1)
        manifest['generation']=2
        manifest['items'][0]['title']='password=hunter22'
        self.assertEqual(self.request('/v1/sync',manifest)[0],422)
        self.assertEqual(self.get_ids('resolve','aabbcc')[1]['items'][0]['title'],'Child')
        self.assertEqual(self.request('/v1/sync',{'surface':'test','sync_source':'manifest example','generation':2,'allow_shrink':True,'items':[]})[0],200)
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
            self.assertIsNone(registry.sha_missing(ref,time.monotonic()-1))
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
        self.reserve('abc124')
        requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'test','version':'1'}}},
                  {'jsonrpc':'2.0','method':'notifications/initialized'},
                  {'jsonrpc':'2.0','id':2,'method':'tools/list'},
                  {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'artifact_resolve','arguments':{'ids':['A#abc123'],'depth':2}}},
                  {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'artifact_search','arguments':{'q':'projection'}}},
                  {'jsonrpc':'2.0','id':5,'method':'tools/call','params':{'name':'artifact_list','arguments':{'surface':'test'}}},
                  {'jsonrpc':'2.0','id':6,'method':'tools/call','params':{'name':'artifact_upsert','arguments':{'id':'abc124','kind':'doc','title':'Created by MCP','surface':'test','links':[{'rel':'explains','to':'abc123'}]}}},
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
        row=self.get_ids('resolve','abc124')[1]['items'][0]
        self.assertEqual(row['links'][0]['rel'],'explains')

    def test_v2_allocation_permanent_and_limit(self):
        status,body=self.request('/v1/artifacts',{'id':'a12345','kind':'doc','title':'Unallocated','surface':'test'})
        self.assertEqual((status,body),(409,{'error':'not_allocated'}))
        self.assertEqual(self.request('/v1/ids',{'surface':'test','count':201})[0],422)
        self.assertEqual(len(self.request('/v1/ids',{'surface':'test','count':200})[1]['ids']),200)
        with psycopg.connect(self.dsn) as db:
            db.execute("UPDATE artifact SET created_at=now()-interval '1 year'")
        self.request('/v1/ids',{'surface':'test'})
        with psycopg.connect(self.dsn) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM artifact').fetchone()[0],201)
        unknown={'surface':'test','sync_source':'test','generation':1,'items':[{'id':'a12345','kind':'doc','title':'Unallocated'}]}
        self.assertEqual(self.request('/v1/sync',unknown),(409,{'error':'not_allocated'}))

    def test_v2_alias_immutability_and_precedence(self):
        self.create(aliases=['Card:18557','EXPLAINER:slug','board:42','card:123456'])
        self.create('123456',title='Canonical number')
        for query in ['card:18557','CARD:18557','18557','Karte 18557','card 18557','explainer:slug','board:42','a%23abc123']:
            self.assertEqual(self.get_ids('resolve',query)[1]['items'][0]['id'],'a#abc123')
        self.assertEqual(self.get_ids('resolve','123456')[1]['items'][0]['title'],'Canonical number')
        self.create(aliases=[])
        self.assertEqual(self.create('abc124',aliases=['CARD:18557']),(409,{'error':'alias_taken'}))
        for statement in ["UPDATE artifact_alias SET artifact_id='abc124' WHERE alias='card:18557'", "DELETE FROM artifact_alias WHERE alias='card:18557'"]:
            with psycopg.connect(self.dsn) as db:
                with self.assertRaises(psycopg.IntegrityError): db.execute(statement)
                db.rollback()
        self.assertEqual(self.get_ids('resolve','18557')[1]['items'][0]['id'],'a#abc123')

    def test_v2_links_depth_and_cycles(self):
        self.create(aliases=['explainer:one'])
        self.create('abc124',links=[{'rel':'explains','to':'explainer:one'}])
        self.create('abc125',links=[{'rel':'depends_on','to':'abc124'}])
        self.create(links=[{'rel':'related','to':'abc125'}])
        result=self.request('/v1/resolve?ids=abc123&depth=0')[1]['items'][0]
        self.assertIn({'rel':'explained_by','to':'a#abc124','note':None},result['links'])
        self.assertNotIn('linked_nodes',result)
        for depth in [1,2]:
            row=self.request('/v1/resolve?ids=abc123&depth='+str(depth))[1]['items'][0]
            ids=[n['id'] for n in row['linked_nodes']]
            self.assertEqual(len(ids),len(set(ids)))
            self.assertNotIn('a#abc123',ids)
            self.assertTrue({'title','summary','kind','status'}<=row['linked_nodes'][0].keys())
        for n in range(20):
            aid=f'{n:06x}'; self.create(aid,links=[{'rel':'related','to':'abc123'}])
        row=self.request('/v1/resolve?ids=abc123&depth=2')[1]['items'][0]
        self.assertEqual(len(row['linked_nodes']),12)
        self.assertEqual(self.request('/v1/resolve?ids=abc123&depth=3')[0],422)
        self.assertEqual(self.create(links=[{'rel':'invalid','to':'abc124'}])[0],422)
        self.assertEqual(self.create(links=[{'rel':'related','to':'ffffff'}])[0],409)
        self.create('abc124',links=[{'rel':'supersedes','to':'abc125'}])
        self.assertIn('superseded_by',[r['rel'] for r in self.get_ids('resolve','abc125')[1]['items'][0]['links']])

    def test_v2_sync_scope_shrink_reactivation_and_refs(self):
        self.reserve('000001','000002','000003','000004')
        self.create('000005',sync_source='other')
        self.create('000006')
        self.request('/v1/artifacts',{'id':'000001','kind':'panel','title':'One','refs':[
            {'kind':'file','target':'/agent','origin':'agent'},
            {'kind':'file','target':'/timer','origin':'timer'}]})
        items=[{'id':f'{n:06x}','kind':'panel','title':str(n),'refs':[{'kind':'file','target':'/manifest'}]} for n in range(1,5)]
        m={'surface':'test','sync_source':'one','generation':'9:'+'a'*40,'sha':'a'*40,'items':items}
        self.assertEqual(self.request('/v1/sync',m)[0],200)
        self.assertEqual(self.request('/v1/sync',m),(409,{'error':'stale_generation'}))
        m['generation']='10:'+'b'*40; m['items']=items[:1]
        self.assertEqual(self.request('/v1/sync',m),(409,{'error':'shrink_refused'}))
        m['allow_shrink']=True
        self.assertEqual(len(self.request('/v1/sync',m)[1]['retired']),3)
        retired=self.get_ids('resolve','000002')[1]['items'][0]
        self.assertEqual(retired['status'],'retired')
        self.create('000002',superseded_by='000001',status='retired')
        self.assertEqual(self.get_ids('resolve','000002')[1]['items'][0]['superseded_by'],'a#000001')
        m.update(generation=11,items={'one':dict(items[0],refs=[]),'two':items[1]})
        self.assertEqual(self.request('/v1/sync',m)[0],200)
        rows=self.get_ids('resolve','000001,000002,000005,000006')[1]['items']
        self.assertEqual([r['status'] for r in rows],['active']*4)
        self.assertEqual({(r['target'],r['origin']) for r in rows[0]['refs']},{('/agent','agent'),('/timer','timer')})
        self.assertIsNotNone(rows[0]['last_synced']); self.assertEqual(rows[0]['deployed_rev'],'a'*40)
        m.update(generation=12,items=[]); m.pop('allow_shrink')
        self.assertEqual(self.request('/v1/sync',m)[0],409)
        m['allow_shrink']=True
        self.assertEqual(len(self.request('/v1/sync',m)[1]['retired']),2)

    def test_v2_sync_full_validation_and_link_aliases(self):
        self.reserve('000001','000002','000003')
        m={'surface':'test','sync_source':'one','generation':1,'items':[
            {'id':'000001','kind':'panel','title':'One','links':[{'rel':'explains','to':'explainer:two'}]},
            {'id':'000002','kind':'panel','title':'Two','aliases':['explainer:two']}]}
        self.assertEqual(self.request('/v1/sync',m)[0],200)
        m.update(generation=2,items=[dict(m['items'][0],title='Changed'),{'id':'000003','kind':'panel','title':'Fine','refs':[{'kind':'file','target':'/bad','origin':[]}]}])
        self.assertEqual(self.request('/v1/sync',m)[0],422)
        self.assertEqual(self.get_ids('resolve','000001')[1]['items'][0]['title'],'One')
        with psycopg.connect(self.dsn) as db:
            self.assertEqual(db.execute("SELECT generation FROM sync_state WHERE surface='test' AND sync_source='one'").fetchone()[0],'1')
            self.assertEqual(db.execute("SELECT status FROM artifact WHERE id='000003'").fetchone()[0],'reserved')
        m.update(generation=2,items=[{'id':'000001','kind':'panel','title':'One','aliases':['board:1']}, {'id':'000002','kind':'panel','title':'Two','aliases':['BOARD:1']}])
        self.assertEqual(self.request('/v1/sync',m),(409,{'error':'alias_taken'}))
        for items in [
            [{'id':'000001','kind':'panel','title':'One','refs':[{'kind':'code','target':[]}]}],
            [{'id':'000001','kind':'panel','title':'One','parent':'000002'}, {'id':'000002','kind':'panel','title':'Two','parent':'000001'}],
            [{'id':'000001','kind':'panel','title':'One','parent':'ffffff'}],
        ]:
            with self.subTest(items=items):
                bad=dict(m,sha='a'*40,items=items,allow_shrink=True)
                self.assertIn(self.request('/v1/sync',bad)[0],(409,422))
        m.update(sync_source='other',generation=3)
        self.assertEqual(self.request('/v1/sync',m),(409,{'error':'owner_mismatch'}))

    def test_v2_summary_guard_every_surface_and_kind(self):
        for extra in [{'surface':'app:any','kind':'doc'}, {'kind':'panel'}, {'kind':'element'}, {'kind':'card'}]:
            for value in ['me@example.org','USD 123','123 BTC','£123','DE89 3704 0044 0532 0130 00','password=example']:
                with self.subTest(extra=extra,value=value): self.assertEqual(self.create(summary=value,**extra)[0],422)
        self.assertEqual(self.create(summary='USD 12',kind='panel')[0],200)
        self.assertEqual(self.create('abc124',summary='36 months forecast',surface='app:any')[0],200)

    def test_v2_pool_offline_refill_and_modes(self):
        import tempfile
        from artifact_cli import pool_action
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as root:
            client=Mock()
            client.request.return_value={'ids':[f'a#{i:06x}' for i in range(200)]}
            self.assertEqual(pool_action('refill','test',client,root),{'count':200})
            path=Path(root)/'pool-test.json'
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            pool_action('refill','test',client,root); self.assertEqual(client.request.call_count,1)
            with patch('artifact_cli.Client',side_effect=AssertionError('offline take must not create client')):
                self.assertEqual(pool_action('take','test',root=root),{'id':'a#000000'})
            path.write_text(json.dumps([f'{i:06x}' for i in range(49)]))
            client.request.return_value={'ids':[f'{i:06x}' for i in range(49,200)]}
            self.assertEqual(pool_action('refill','test',client,root),{'count':200})
            self.assertEqual(client.request.call_args.args[1]['count'],151)
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=8) as executor:
                taken=list(executor.map(lambda _:pool_action('take','test',root=root)['id'],range(20)))
            self.assertEqual(len(set(taken)),20)
            self.assertEqual(len(json.loads(path.read_text())),180)
            path.write_text('[]')
            with self.assertRaisesRegex(ValueError,'pool empty'): pool_action('take','test',root=root)

    def test_v2_verify_refs_pinned_and_head(self):
        import tempfile
        import os
        from artifact_cli import check_code_ref,verify_refs
        with tempfile.TemporaryDirectory() as root:
            def git(*args):
                return subprocess.run(['git','-C',root,*args],check=True,text=True,capture_output=True).stdout.strip()
            git('init'); git('config','user.email','test@example.org'); git('config','user.name','Test')
            (Path(root)/'code.py').write_text('print(1)\n'); git('add','.'); git('commit','-m','initial')
            sha=git('rev-parse','HEAD')
            ref={'kind':'code','target':f'github:example/local@{sha}:code.py','pinned_sha':sha}
            self.assertIsNone(check_code_ref(ref,{'example/local':root}))
            self.create(refs=[ref])
            with patch.dict(os.environ,ARTIFACTS_URL=self.base,ARTIFACTS_AGENT_TOKEN='test-all'):
                self.assertEqual(verify_refs(Client(),{'example/local':root}),{'checked':1,'stale':0,'conflicts':0})
                (Path(root)/'code.py').unlink(); git('add','.'); git('commit','-m','remove')
                self.assertEqual(verify_refs(Client(),{'example/local':root}),{'checked':1,'stale':1,'conflicts':0})
            row=self.get_ids('resolve','abc123')[1]['items'][0]
            self.assertIsNotNone(row['refs_verified_at']); self.assertIn('HEAD',row['stale_reason']); self.assertTrue(row['stale'])
            self.assertIn('pinned sha',check_code_ref(dict(ref,pinned_sha='f'*40),{'example/local':root}))
            with patch('artifact_cli.subprocess.run') as run:
                run.return_value.returncode=0
                self.assertIsNone(check_code_ref(ref,{})); self.assertEqual(run.call_count,2)
                self.assertEqual(run.call_args.args[0][0:2],['gh','api'])
            self.assertEqual(self.request('/v1/verify-refs',{'id':'abc123','refs':[],'stale_reason':None})[0],409)

    def test_fix_atomic_migration_preflight_grants_and_delete(self):
        root=Path(__file__).resolve().parents[1]
        with psycopg.connect(self.dsn,autocommit=True) as db:
            db.execute('CREATE SCHEMA migration_probe')
            try:
                db.execute('SET search_path TO migration_probe,public')
                db.execute((root/'migrations/001_init.sql').read_text())
                db.execute("INSERT INTO artifact(id,kind,title,surface) VALUES('aaaaaa','doc','A','test'),('bbbbbb','doc','B','test')")
                db.execute("INSERT INTO artifact_alias VALUES('Card:1','aaaaaa'),('card:1','bbbbbb')")
                db.execute("INSERT INTO token(name,hash,scopes) VALUES('sync','x',ARRAY['read']),('agent','y',ARRAY['write']),('other','z',ARRAY['write'])")
                with self.assertRaisesRegex(psycopg.errors.RaiseException,'case-variant alias duplicates: card:1'):
                    db.execute((root/'migrations/002_v2.sql').read_text())
                db.execute('ROLLBACK')
                self.assertIsNone(db.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='migration_probe' AND table_name='token' AND column_name='surfaces'").fetchone())
                self.assertIsNone(db.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='migration_probe' AND table_name='artifact_ref' AND column_name='origin'").fetchone())
                db.execute("DELETE FROM artifact_alias WHERE alias='Card:1'")
                db.execute((root/'migrations/002_v2.sql').read_text())
                scopes=dict(db.execute('SELECT name,scopes FROM token').fetchall())
                self.assertEqual(scopes,{'sync':['read','sync'],'agent':['write','sync'],'other':['write']})
                self.assertTrue(all('admin' not in v for v in scopes.values()))
                with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                    db.execute("DELETE FROM artifact WHERE id='bbbbbb'")
                # Documented v1 rollback: dropping this trigger allows alias rewrites.
                db.execute('DROP TRIGGER artifact_alias_immutable ON artifact_alias')
                db.execute("DELETE FROM artifact_alias WHERE alias='card:1'")
                db.execute("INSERT INTO artifact_alias VALUES('card:1','bbbbbb')")
            finally:
                db.execute('ROLLBACK')
                db.execute('SET search_path TO public')
                db.execute('DROP SCHEMA migration_probe CASCADE')

    def test_fix_scopes_surfaces_generation_and_admin_reset(self):
        import time
        with psycopg.connect(self.dsn) as db:
            for name,scopes,surfaces in [('scoped',['read','write','sync'],['app:owned*','exact']),('sync-only',['sync'],['app:owned*']),('admin-only',['admin'],['app:owned*'])]:
                db.execute('INSERT INTO token(name,hash,scopes,surfaces) VALUES(%s,%s,%s,%s) ON CONFLICT(name) DO UPDATE SET scopes=EXCLUDED.scopes,surfaces=EXCLUDED.surfaces',
                           (name,hashlib.sha256(('test-'+name).encode()).hexdigest(),scopes,surfaces))
        self.server.token_cache.clear()
        m={'surface':'app:owned-one','sync_source':'m','generation':1,'items':[],'allow_shrink':True}
        self.assertEqual(self.request('/v1/sync',m,token='writer')[0],403)
        self.assertEqual(self.request('/v1/sync',m,token='sync-only')[0],200)
        self.assertEqual(self.request('/v1/ids',{'surface':m['surface']},token='sync-only')[0],403)
        self.assertEqual(self.request('/v1/sync',dict(m,surface='app:other'),token='scoped')[0],403)
        for value in (10**20-1,str(int(time.time())+86401)+':'+'a'*40):
            self.assertEqual(self.request('/v1/sync',dict(m,generation=value),token='scoped')[0],422)
        reset={'surface':m['surface'],'sync_source':'m'}
        self.assertEqual(self.request('/v1/admin/sync-reset',reset,token='scoped')[0],403)
        self.assertEqual(self.request('/v1/admin/sync-reset',dict(reset,surface='app:other'),token='admin-only')[0],403)
        self.assertEqual(self.request('/v1/admin/sync-reset',reset,token='admin-only')[0],200)
        self.assertEqual(self.request('/v1/sync',m,token='sync-only')[0],200)
        for surface,status in [('app:owned-one',200),('exact',200),('exact-more',403),('app:other',403)]:
            self.assertEqual(self.request('/v1/ids',{'surface':surface},token='scoped')[0],status)
            self.assertEqual(self.request('/v1/artifacts',{'kind':'doc','title':'A','surface':surface},token='scoped')[0],status)
        self.create('aaaaaa',surface='app:other')
        self.create('bbbbbb',surface='app:owned-one')
        self.assertEqual(self.request('/v1/artifacts/bbbbbb',{'links':[{'rel':'related','to':'aaaaaa'}]},method='PUT',token='scoped')[0],403)
        self.assertEqual(self.request('/v1/artifacts/aaaaaa',{'title':'Changed'},method='PUT',token='scoped')[0],403)
        self.assertEqual(self.request('/v1/artifacts/aaaaaa',{'surface':'app:owned-one'},method='PUT',token='scoped')[0],409)

    def test_fix_ref_origins_and_all_nonpublic_guards(self):
        self.create()
        self.assertEqual(self.request('/v1/artifacts/abc123',{'refs':[{'kind':'file','target':'/a','origin':'manifest'}]},method='PUT',token='writer')[0],200)
        self.assertEqual(self.get_ids('resolve','abc123')[1]['items'][0]['refs'][0]['origin'],'agent')
        self.assertEqual(self.request('/v1/artifacts/abc123',{'refs':[{'kind':'file','target':'/timer','origin':'timer'}]},method='PUT',token='writer')[0],403)
        self.assertEqual(self.request('/v1/artifacts/abc123',{'refs':[{'kind':'file','target':'/timer','origin':'timer'}]},method='PUT')[0],200)
        self.assertEqual({r['origin'] for r in self.get_ids('resolve','abc123')[1]['items'][0]['refs']},{'agent','timer'})
        for access in ('private','internal'):
            for data in ({'title':'Revenue EUR 250000'}, {'summary':'Revenue EUR 250000'}, {'refs':[{'kind':'file','target':'/a','label':'EUR 123456'}]}):
                self.assertEqual(self.request('/v1/artifacts',dict({'kind':'doc','title':'Doc','surface':'job:z','access':access},**data))[0],422)
        self.assertEqual(self.request('/v1/artifacts',{'kind':'doc','title':'Revenue EUR 250000','surface':'job:z','access':'public'})[0],200)
        self.create('bbbbbb')
        for value in ('https://u:p@example.com/x','https://example.com/?token=abc','api_key=private'):
            for field in ('url','selector'):
                self.assertEqual(self.request('/v1/artifacts/abc123',{field:value},method='PUT')[0],422)
            self.assertEqual(self.request('/v1/artifacts/abc123',{'links':[{'rel':'related','to':'bbbbbb','note':value}]},method='PUT')[0],422)
        self.assertEqual(self.request('/v1/artifacts/abc123',{'refs':[{'kind':'file','target':'/a','label':'sk-abcdefghijkl'}]},method='PUT')[0],422)
        for target in ('github:../repo@'+'a'*40+':x','github:owner/.@'+'a'*40+':x'):
            self.assertEqual(self.request('/v1/artifacts/abc123',{'refs':[{'kind':'code','target':target}]},method='PUT')[0],422)

    def test_fix_auth_preflight_connection_capacity_cache(self):
        import registry
        from unittest.mock import MagicMock
        with patch('registry.psycopg.connect') as connect:
            for token in (None,'x'*600):
                self.assertEqual(self.request('/v1/list',token=token)[0],401)
            connect.assert_not_called()
        for _ in range(8): self.assertTrue(self.server.connections.acquire(blocking=False))
        try:
            with patch('registry.psycopg.connect') as connect:
                self.assertEqual(self.request('/v1/list')[0],503)
                connect.assert_not_called()
        finally:
            for _ in range(8): self.server.connections.release()
        db=MagicMock(); db.execute.return_value=[{'name':'cached','hash':'a'*64,'scopes':['read'],'surfaces':None}]
        self.server.token_cache.clear()
        with patch('registry.time.monotonic',return_value=100):
            self.assertEqual(self.server.authenticate(db,'a'*64)['name'],'cached')
        with patch('registry.time.monotonic',return_value=159): self.server.authenticate(db,'a'*64)
        self.assertEqual(db.execute.call_count,1)
        with patch('registry.time.monotonic',return_value=161): self.server.authenticate(db,'a'*64)
        self.assertEqual(db.execute.call_count,2)
        self.server.token_cache.clear()

    def test_fix_surface_reserved_quota_atomic(self):
        with psycopg.connect(self.dsn) as db:
            db.execute("INSERT INTO artifact(id,kind,title,surface,status) SELECT lpad(to_hex(n),6,'0'),'element','','quota','reserved' FROM generate_series(1,1999) n")
        self.assertEqual(self.request('/v1/ids',{'surface':'quota','count':2})[0],429)
        with psycopg.connect(self.dsn) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM artifact WHERE surface='quota'").fetchone()[0],1999)
        self.assertEqual(self.request('/v1/ids',{'surface':'quota'})[0],200)
        self.assertEqual(self.request('/v1/ids',{'surface':'quota'})[0],429)
        self.assertEqual(self.request('/v1/ids',{'surface':'different'})[0],200)
        self.assertEqual(self.request('/v1/artifacts/000001',{'kind':'doc','title':'Activated'},method='PUT')[0],200)
        self.assertEqual(self.request('/v1/ids',{'surface':'quota'})[0],200)

    def test_fix_sha_unknown_optional_token_and_dot_segments(self):
        import registry,time,os
        from unittest.mock import MagicMock
        ref={'kind':'code','target':'github:owner/repo@'+'a'*40+':x'}
        self.sha_patch.stop()
        try:
            opener=MagicMock()
            for error in (urllib.error.HTTPError('https://api.github.com',404,'hidden',{},None),urllib.error.HTTPError('https://api.github.com',403,'rate',{},None),OSError('offline')):
                registry._SHA_CACHE.clear(); opener.open.side_effect=error
                with patch('registry.urllib.request.build_opener',return_value=opener),patch.dict(os.environ,{'GITHUB_TOKEN':'test-optional-token'}):
                    self.assertIsNone(registry.sha_missing(ref,time.monotonic()+2))
                    self.assertEqual(opener.open.call_args.args[0].get_header('Authorization'),'Bearer test-optional-token')
            for target in ('github:../repo@'+'a'*40+':x','github:owner/.@'+'a'*40+':x'):
                with patch('registry.urllib.request.build_opener') as build:
                    self.assertIsNone(registry.sha_missing(dict(ref,target=target),time.monotonic()+2))
                    build.assert_not_called()
            self.create(refs=[ref])
            registry._SHA_CACHE.clear(); opener.open.side_effect=OSError('offline')
            with patch('registry.urllib.request.build_opener',return_value=opener):
                self.assertFalse(self.get_ids('resolve','abc123')[1]['items'][0]['stale'])
        finally:
            registry._SHA_CACHE.clear(); self.sha_patch.start()

    def test_fix_cli_sync_git_fallback_keyed_and_override(self):
        import tempfile
        from artifact_cli import sync_manifest,main
        with tempfile.TemporaryDirectory(prefix='p1b-fix-sync-') as root:
            def git(*args): return subprocess.run(['git','-C',root,*args],capture_output=True,text=True,check=True).stdout.strip()
            git('init','-q'); git('config','user.email','test@example.invalid'); git('config','user.name','Test')
            path=Path(root)/'manifest.json'
            path.write_text(json.dumps({'surface':'app:test','sync_source':'m','items':{'panel':{'id':'abcdef','kind':'panel','title':'Panel'}}}))
            git('add','.'); git('commit','-qm','manifest')
            data=sync_manifest(path)
            self.assertEqual(data['generation'],git('log','-1','--format=%ct:%H'))
            self.assertIsInstance(data['items'],dict)
            self.assertEqual(sync_manifest(path,'123:'+'a'*40)['generation'],'123:'+'a'*40)
            with patch('artifact_cli.Client') as client,contextlib.redirect_stdout(io.StringIO()):
                client.return_value.request.return_value={'ids':[]}
                self.assertEqual(main(['sync',str(path),'--generation','123']),0)
                self.assertEqual(client.return_value.request.call_args.args[1]['generation'],'123')
            with patch('artifact_cli.subprocess.run',side_effect=OSError),patch('artifact_cli.time.time',return_value=123):
                self.assertEqual(sync_manifest(path)['generation'],123)

    def test_fix_cli_add_ref_preserves_other_origin_ownership(self):
        from artifact_cli import main
        refs=[{'kind':'file','target':'/'+origin,'origin':origin} for origin in ('manifest','agent','timer')]
        with patch('artifact_cli.Client') as client,contextlib.redirect_stdout(io.StringIO()):
            client.return_value.resolve.return_value={'items':[{'id':'a#abcdef','refs':refs}]}
            client.return_value.upsert.return_value={'id':'a#abcdef'}
            self.assertEqual(main(['add-ref','abcdef','file=/new']),0)
            self.assertEqual([r['target'] for r in client.return_value.upsert.call_args.args[0]['refs']],['/agent','/new'])

    def test_fix_cli_dot_repos_and_per_row_conflict(self):
        from artifact_cli import RegistryHTTPError,check_code_ref,verify_refs
        from unittest.mock import MagicMock
        for target in ('github:../repo@'+'a'*40+':x','github:owner/.@'+'a'*40+':x'):
            with patch('artifact_cli.subprocess.run') as run:
                self.assertEqual(check_code_ref({'target':target},{}),'invalid code repository')
                self.assertEqual(expand_ref({'kind':'code','target':target}),'[invalid code repository]')
                run.assert_not_called()
        client=MagicMock()
        client.request.side_effect=[{'items':[{'id':'aaaaaa','refs':[]},{'id':'bbbbbb','refs':[]}]},RegistryHTTPError(409,'refs_changed'),{'id':'bbbbbb'},{'items':[]}]
        self.assertEqual(verify_refs(client),{'checked':1,'stale':0,'conflicts':1})
        self.assertEqual(client.request.call_args.kwargs,{'after':'bbbbbb'})
        client.request.side_effect=[{'items':[{'id':'aaaaaa','refs':[]}]},RegistryHTTPError(503,'unavailable')]
        with self.assertRaises(RegistryHTTPError): verify_refs(client)

    def test_devices_and_learned_delete(self):
        import time
        body={'hash':'a'*64,'label':'Laptop','scopes':['screen','dictate'],'expires_at':int(time.time()*1000)+600000}
        self.assertEqual(self.request('/v1/devices',body,token='reader')[0],403)
        status, row=self.request('/v1/devices',body,token='desk'); self.assertEqual(status,200)
        did=row['id']
        self.assertEqual(self.request('/v1/devices',body,token='desk')[0],409)
        status, listed=self.request('/v1/devices',token='desk'); self.assertEqual(status,200)
        self.assertNotIn('hash',listed['devices'][0])
        for _ in range(2): self.assertEqual(self.request('/v1/devices/verify',{'hash':'a'*64},token='desk')[0],200)
        with psycopg.connect(self.dsn) as db:
            seen=db.execute('SELECT last_seen FROM device WHERE id=%s',(did,)).fetchone()[0]
        self.request('/v1/devices/verify',{'hash':'a'*64},token='desk')
        with psycopg.connect(self.dsn) as db:
            self.assertEqual(db.execute('SELECT last_seen FROM device WHERE id=%s',(did,)).fetchone()[0],seen)
        self.assertEqual(self.request('/v1/devices/'+did,token='desk',method='DELETE')[0],200)
        self.assertEqual(self.request('/v1/devices/verify',{'hash':'a'*64},token='desk')[0],404)
        body['hash']='b'*64
        _,row=self.request('/v1/devices',body,token='desk')
        with psycopg.connect(self.dsn) as db: db.execute("UPDATE device SET expires_at=now()-interval '1 second' WHERE id=%s",(row['id'],))
        self.assertEqual(self.request('/v1/devices/verify',{'hash':'b'*64},token='desk')[0],404)
        self.request('/v1/dictionary',{'term':'Learned','source':'learned'},token='desk')
        self.request('/v1/dictionary',{'term':'Manual','source':'manual'},token='desk')
        self.assertEqual(self.request('/v1/dictionary/Learned',token='reader',method='DELETE')[0],403)
        self.assertEqual(self.request('/v1/dictionary/Manual',token='desk',method='DELETE')[0],404)
        self.assertEqual(self.request('/v1/dictionary/Learned',token='desk',method='DELETE')[0],200)

if __name__=='__main__': unittest.main()
