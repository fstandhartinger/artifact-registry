import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"bin"))
from artifact_ids import normalise, find_ids
from artifact_cli import allowed_file, expand_ref, redact

class IdTests(unittest.TestCase):
    def test_normalise(self):
        for value in ['A#AbC123','abc123',' a#ABC123 ']: self.assertEqual(normalise(value),'abc123')
        for value in ['a#abc12','abcdefg','a #abc123',None,'zzzzzz']:
            with self.assertRaises(ValueError): normalise(value)
    def test_ocr(self):
        self.assertEqual(find_ids('A#ABC123 ä #oI|sGq a#abcdef a#abcdef'),['a#abc123','a#abcdef','a#011599'])
        self.assertEqual(find_ids('xa#abcdef a#abcdef1 a#123456z'),[])
        self.assertEqual(find_ids('A # B8C3FF'),'a#b8c3ff'.split())
        import json
        for case in json.loads((Path(__file__).resolve().parents[1]/'testdata/ocr-ids.json').read_text()):
            with self.subTest(text=case['text']): self.assertEqual(find_ids(case['text']),case['ids'])
    def test_expansion_boundary(self):
        with self.assertRaises(ValueError): allowed_file('/etc/passwd','private')
        with self.assertRaises(ValueError): allowed_file(str(Path.home()/'.config/dev-secrets.env'),'private')
        self.assertEqual(expand_ref({'kind':'file','target':'/etc/passwd'}),'[reference unavailable or refused]')
        self.assertNotIn('abcdefgh12345678',redact('password=abcdefgh12345678'))
        self.assertNotIn('abcdefgh12345678',redact('Bearer abcdefgh12345678'))



class IbanGuardTest(unittest.TestCase):
    def test_iban_detection_without_prose_false_positives(self):
        import importlib.util, pathlib
        spec = importlib.util.spec_from_file_location('reg_iban', pathlib.Path(__file__).resolve().parents[1] / 'registry.py')
        reg = importlib.util.module_from_spec(spec); spec.loader.exec_module(reg)
        self.assertTrue(reg.has_iban('Konto DE89 3704 0044 0532 0130 00'))
        self.assertTrue(reg.has_iban('konto de89370400440532013000'))
        for prose in ('SN92 ist eines seiner Teilnetze', 'SN92 unter den Subnets von Bittensor', 'SN92 ist das Subnet 92. So'):
            self.assertFalse(reg.has_iban(prose), prose)
