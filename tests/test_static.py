import threading
import unittest
import urllib.error
import urllib.request
from registry import Server

class StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Static files and missing auth must never require a database connection.
        cls.server=Server(('127.0.0.1',0),'invalid-dsn')
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def test_anonymous_assets(self):
        for name,mime in [('js','text/javascript'),('css','text/css')]:
            with urllib.request.urlopen(self.base+'/static/artifact-badge.'+name+'?v=1') as res:
                self.assertEqual(res.status,200)
                self.assertEqual(res.headers['Content-Type'],mime+'; charset=utf-8')
                self.assertEqual(res.headers['Cache-Control'],'public, max-age=3600')
                self.assertEqual(res.headers['X-Content-Type-Options'],'nosniff')
                self.assertGreater(len(res.read()),100)
    def test_allowlist_and_auth_boundary(self):
        for path,status in [('/static/',404),('/static/../registry.py',404),('/static/%2e%2e/registry.py',404),('/static/registry.py',404),('/v1/list',401),('/registry.py',401)]:
            with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(self.base+path)
            self.assertEqual(error.exception.code,status)
        request=urllib.request.Request(self.base+'/static/artifact-badge.js',data=b'{}')
        with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(request)
        self.assertEqual(error.exception.code,401)
