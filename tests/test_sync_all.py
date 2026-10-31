import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from artifact_sync_all import fetch_manifest, run
from artifact_cli import RegistryHTTPError


class SyncAllTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        fake=self.root/'gh'
        fake.write_text('''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['GH_CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
if os.environ.get('GH_FAIL'): sys.exit(1)
if '/commits/' in sys.argv[2]:
 print(json.dumps({'sha':'a'*40,'commit':{'committer':{'date':'2026-10-30T00:00:00Z'}}}))
else:
 print(os.environ['GH_MANIFEST'])
'''); fake.chmod(0o755)
        env=patch.dict(os.environ,PATH=str(self.root)+os.pathsep+os.environ['PATH'],GH_CALLS=str(self.root/'calls'),GH_MANIFEST=json.dumps({'panel':{'id':'abcdef','kind':'panel','title':'Panel'}}))
        env.start(); self.addCleanup(env.stop)
        self.source={'repo':'owner/repo','path':'src/artifacts.manifest.json','branch':'feature/a','surface':'app:test','alias_prefix':'earnings:','access':'private'}

    def test_legacy_immutable_fetch_and_defaults(self):
        data=fetch_manifest(self.source)
        self.assertEqual(data['generation'],'1793318400:'+'a'*40)
        self.assertEqual(data['sync_source'],'github:owner/repo/src/artifacts.manifest.json')
        self.assertEqual(data['items']['panel']['aliases'],['earnings:panel'])
        self.assertEqual(data['items']['panel']['access'],'private')
        calls=[json.loads(line) for line in (self.root/'calls').read_text().splitlines()]
        self.assertIn('feature%2Fa',calls[0][1])
        self.assertIn('?ref='+'a'*40,calls[1][1])
        self.assertEqual(calls[1][-1],'Accept: application/vnd.github.raw+json')

    def test_modern_and_surface_mismatch(self):
        modern={'surface':'app:test','items':{'panel':{'id':'abcdef'}}}
        with patch.dict(os.environ,GH_MANIFEST=json.dumps(modern)):
            self.assertEqual(fetch_manifest(self.source)['items']['panel']['id'],'abcdef')
            with self.assertRaises(ValueError): fetch_manifest(dict(self.source,surface='other'))

    def test_stale_only_is_success_and_other_errors_continue(self):
        sources=self.root/'sources'; log=self.root/'log'
        sources.write_text(json.dumps([self.source]*3))
        client=Mock(); client.request.side_effect=[RegistryHTTPError(409,'stale_generation'),RegistryHTTPError(409,'owner_mismatch'),{}]
        self.assertEqual(run(sources,log,client),1)
        self.assertEqual([json.loads(line)['status'] for line in log.read_text().splitlines()],['no change','error','synced'])
        self.assertEqual(client.request.call_count,3)
        sources.write_text(json.dumps([self.source]))
        client.request.side_effect=RegistryHTTPError(409,'stale_generation')
        self.assertEqual(run(sources,log,client),0)

    def test_invalid_source_does_not_fetch(self):
        with self.assertRaises(ValueError): fetch_manifest(dict(self.source,path='../secret'))
        self.assertFalse((self.root/'calls').exists())

    def test_github_failure_logs_one_safe_line(self):
        sources=self.root/'sources'; log=self.root/'log'
        sources.write_text(json.dumps([self.source]))
        client=Mock()
        with patch.dict(os.environ,GH_FAIL='yes'):
            self.assertEqual(run(sources,log,client),1)
        client.request.assert_not_called()
        self.assertEqual(json.loads(log.read_text())['status'],'error')

    def test_modern_list_kept_without_alias_prefix(self):
        source={k:v for k,v in self.source.items() if k!='alias_prefix'}
        with patch.dict(os.environ,GH_MANIFEST=json.dumps({'surface':'app:test','items':[{'id':'abcdef'}]})):
            data=fetch_manifest(source)
            self.assertEqual(list(data['items'].values()),[{'id':'abcdef','access':'private'}])
