"""All fixtures are synthetic and offline; no installed provider libraries required."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from evidence_core import ContractError
from expansion_runner import partition_components,seal_evidence,validate_checkpoint
from source_acquisition import encoded,sha256
from p4_audit import calendar_in_scope
from dataset_contract import compact_payload,expand_payload,pack


class ExpansionRunnerTests(unittest.TestCase):
    def test_compact_payload_roundtrip_keeps_strings_integers_and_nested_evidence(self):
        row=pack({'doc_id':'S0000001','candidate_id':'a'*64,'metric':'revenue','normalized_value':'1.00',
                  'public_available_at':'2022-01-01T00:00:00+09:00','element_index':3,
                  'nested':{'payload':{},'projected_columns':['not_an_instruction']},'synthetic':True})
        self.assertEqual(expand_payload(compact_payload(row)),row)
        row=pack({'input_line':1})
        self.assertEqual(expand_payload(compact_payload(row)),row)

    def test_compact_payload_rejects_invalid_reference(self):
        row=pack({'synthetic':True})
        row['payload_json']=encoded({'payload':{},'projected_columns':['absent']}).decode()
        with self.assertRaisesRegex(ContractError,'payload_projection_invalid'):expand_payload(row)

    def test_calendar_scope_keeps_complete_finite_search_window(self):
        days=['2022-02-01']
        self.assertTrue(calendar_in_scope('2022-01-17',days))
        self.assertTrue(calendar_in_scope('2022-02-15',days))
        self.assertFalse(calendar_in_scope('2022-01-16',days))
        self.assertFalse(calendar_in_scope('2022-02-16',days))

    def test_whole_revision_components_are_deterministic(self):
        c=[{'A','B','C'},{'D'},{'E','F'}];months={x:'2022-01' for x in 'ABCDEF'}
        a=list(partition_components(c,months,limit=3));b=list(partition_components(list(reversed(c)),months,limit=3))
        self.assertEqual(a,b);self.assertEqual(a[0]['doc_ids'],['A','B','C'])
        self.assertEqual(sorted(x for p in a for x in p['doc_ids']),list('ABCDEF'))

    def test_excessive_component_remains_blocked_not_substituted(self):
        c={str(x) for x in range(101)}
        p=list(partition_components([c],dict.fromkeys(c,'2022-01')))
        self.assertEqual(p[0]['status'],'BLOCKED');self.assertEqual(len(p[0]['doc_ids']),101)

    def test_month_boundaries_remain_distinct(self):
        p=list(partition_components([{'a'},{'b'}],{'a':'2020-01','b':'2021-01'}))
        self.assertEqual(len(p),2)

    def test_stage_archive_roundtrip_preserves_original_bytes_and_mtime(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);work=root/'work';work.mkdir();p=work/'rows.jsonl'
            data=encoded({'synthetic':True,'original_value':'123.00'})+b'\n';p.write_bytes(data);before=p.stat().st_mtime_ns
            proof=seal_evidence(work,root/'evidence.zip')
            self.assertEqual(proof['roundtrip'],'PASS');self.assertEqual(p.read_bytes(),data);self.assertEqual(p.stat().st_mtime_ns,before)
            with zipfile.ZipFile(root/'evidence.zip') as z:self.assertEqual(z.read('rows.jsonl'),data)

    def test_checkpoint_resume_rechecks_bytes_and_plan(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'a').write_bytes(b'synthetic');r={'status':'COMPLETE','plan_sha256':'fixed','artifacts':{'a':sha256(b'synthetic')}}
            (root/'result.json').write_bytes(encoded(r));self.assertEqual(validate_checkpoint(root,'fixed'),r)
            with self.assertRaisesRegex(ContractError,'checkpoint_plan_changed'):validate_checkpoint(root,'other')
            (root/'a').write_bytes(b'changed')
            with self.assertRaisesRegex(ContractError,'checkpoint_artifact_changed'):validate_checkpoint(root,'fixed')


if __name__=='__main__':unittest.main()
