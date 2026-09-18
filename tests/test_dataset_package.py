"""Offline synthetic package tests. The fixture codec is explicitly not Parquet.

Real Parquet is separately exercised by the private acceptance run, using the
existing hash-locked optional dependency. CI never opens a private dataset.
"""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
import unittest

from dataset_contract import SCHEMA, pack, payload, safe_path
from dataset_export import export_dataset, build_tables
from dataset_validation import resolve_current, read_snapshot, validate_snapshot, validate_tables
from evidence_core import ContractError
from metadata_gap_audit import snapshot_fingerprints
from query_dataset import Dataset
from source_acquisition import encoded, sha256
import test_dated_pit as dated_fixture


class FixtureCodec:
    format='synthetic_jsonl'
    extension='.jsonl'
    def encode(self, rows): return b''.join(encoded(r)+b'\n' for r in rows)
    def decode(self, raw): return [json.loads(line) for line in raw.splitlines()]


class DatasetPackageTests(unittest.TestCase):
    def setUp(self):
        fixture=dated_fixture.DatedPrivateAuditTests()
        with redirect_stdout(io.StringIO()): fixture.setUp();fixture.audit()
        self.addCleanup(fixture.doCleanups)
        self.base=fixture.base;self.p3=fixture.p3;self.p4=self.base/'dated/synthetic-dated'
        self.p5=self.base/'p5';self.p5.mkdir();self.root=self.base/'package';self.codec=FixtureCodec()
        plan=json.loads((self.p3/'audit_plan.json').read_bytes())
        self.write(self.p5,'audit_plan.json',{'snapshot_id':'synthetic-p5','p3_snapshot_id':plan['snapshot_id'],
            'definition_version':'synthetic-p5-v1','synthetic':True})
        self.write(self.p5,'preservation_proof.json',{'p3_before':snapshot_fingerprints(self.p3)})
        self.write(self.p5,'source_acceptance.json',{'sources':[{'source_id':'numad','rights_reviewed':'BLOCKED'}]})
        self.facts=self.read_lines(self.p3/'canonical_facts.jsonl');f=self.facts[0];self.fact=f
        common={'doc_id':f['doc_id'],'synthetic':True,'source_id':'numad','source_class':'derived_from_edinet'}
        self.write_lines(self.p5/'derived_observations.jsonl',[dict(common,source_row_id='synthetic-source',table='text_blocks',
            provider_fields={'doc_id':f['doc_id'],'tag':'SyntheticTextBlock','text':'SYNTHETIC PRIVATE TEXT'},locator={'line_number':1})])
        self.write_lines(self.p5/'official_observations.jsonl',[dict(common,origin_id='synthetic-origin',value='SYNTHETIC PRIVATE TEXT',
            member=f['xbrl_member'],member_sha256=f['xbrl_member_sha256'],artifact_sha256=f['source_artifact_sha256'],element_index=1)])
        self.write_lines(self.p5/'comparison_ledger.jsonl',[dict(common,comparison_id='synthetic-comparison',source_row_id='synthetic-source',
            origin_ids=['synthetic-origin'],canonical_fact_ids=[f['fact_id']],component_row_ids=[],comparison='text_difference',
            status='BLOCKED',missing_reason='synthetic_text_difference',independent_evidence_increment=0,canonical_mapping_promoted=False)])
        self.write_lines(self.p5/'failure_ledger.jsonl',[dict(common,reason='synthetic_text_difference')])

    @staticmethod
    def write(root, name, value): (root/name).write_bytes(encoded(value)+b'\n')
    @staticmethod
    def write_lines(path, rows): path.write_bytes(b''.join(encoded(r)+b'\n' for r in rows))
    @staticmethod
    def read_lines(path): return [json.loads(r) for r in path.read_bytes().splitlines()]
    def export(self,snapshot='synthetic-one',**kwargs):
        return export_dataset(self.p3,self.p4,self.p5,kwargs.pop('root',self.root),snapshot,codec=self.codec,synthetic=True,**kwargs)
    def load(self): return Dataset(self.root,codec=self.codec,allow_synthetic=True)
    def change_manifest(self, change):
        path=self.root/'snapshots/synthetic-one/manifest.json'
        m=json.loads(path.read_bytes());change(m);path.write_bytes(encoded(m)+b'\n')
        c=json.loads((self.root/'CURRENT.json').read_bytes());c['manifest_sha256']=sha256(path.read_bytes());c['manifest_byte_count']=path.stat().st_size
        self.write(self.root,'CURRENT.json',c)

    def test_stable_ids_and_lineage_roundtrip(self):
        before={p:snapshot_fingerprints(p) for p in (self.p3,self.p4,self.p5)}
        result=self.export();self.assertEqual(result['status'],'PASS');d=self.load()
        self.assertEqual(d.rows('canonical_facts'),self.facts)
        for table,file,root in [('pit_join_rows','pit_join_rows.jsonl',self.p4),('securities','security_identity_map.jsonl',self.p4),
            ('derived_source_links','comparison_ledger.jsonl',self.p5)]: self.assertEqual(d.rows(table),self.read_lines(root/file))
        self.assertEqual(before,{p:snapshot_fingerprints(p) for p in before})
        j=d.rows('pit_join_rows')[0];trace=d.lineage('pit_join_rows',j['research_row_id'])
        self.assertTrue({'canonical_facts','original_locators','securities','jquants_source_rows','market_observations'} <= {n['table'] for n in trace['nodes']})
        c=d.lineage('derived_source_links','synthetic-comparison')
        self.assertIn('original_facts',{n['table'] for n in c['nodes']})

    def test_current_advances_without_old_snapshot_or_index_changes(self):
        self.export();old=resolve_current(self.root);before=snapshot_fingerprints(old);index=(self.root/'dataset_index.json').read_bytes()
        self.export('synthetic-two')
        self.assertEqual(resolve_current(self.root).name,'synthetic-two')
        self.assertEqual(before,snapshot_fingerprints(old));self.assertEqual(index,(self.root/'dataset_index.json').read_bytes())

    def test_old_snapshot_overwrite_rejected_even_with_same_input(self):
        self.export();before=snapshot_fingerprints(self.root)
        with self.assertRaisesRegex(ContractError,'snapshot_already_exists'): self.export()
        self.assertEqual(before,snapshot_fingerprints(self.root))

    def test_manifest_hash_checked_before_queries(self):
        self.export();p=self.root/'snapshots/synthetic-one/manifest.json';p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaisesRegex(ContractError,'manifest_hash_mismatch'):self.load()

    def test_artifact_hash_blocks_corruption(self):
        self.export();p=self.root/'snapshots/synthetic-one/entities.jsonl';p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaisesRegex(ContractError,'artifact_integrity_failed'):self.load()

    def test_row_count_is_verified_separately_from_bytes(self):
        self.export();self.change_manifest(lambda m:m['artifacts'][0].update(row_count=999))
        with self.assertRaisesRegex(ContractError,'row_count_mismatch'):self.load()

    def test_schema_is_verified_separately_from_bytes(self):
        self.export();self.change_manifest(lambda m:m['artifacts'][0].update(schema_hash='0'*64))
        with self.assertRaisesRegex(ContractError,'schema_hash_mismatch'):self.load()

    def test_pit_before_and_after_revision_has_no_future_or_old_fallback(self):
        self.export();d=self.load();docs=sorted(d.rows('documents'),key=lambda r:r['public_available_at'])
        entity='edinet:'+docs[0]['edinet_code']
        before=d.facts(entity,docs[1]['public_available_at'])
        after=d.facts(entity,(datetime.fromisoformat(docs[1]['public_available_at'])+timedelta(seconds=1)).isoformat())
        self.assertEqual({f['doc_id'] for f in before['facts']},{docs[0]['doc_id']})
        self.assertEqual({f['doc_id'] for f in after['facts']},{docs[1]['doc_id']})

    def test_null_revision_does_not_fall_back(self):
        self.export();d=self.load();docs=sorted(d.rows('documents'),key=lambda r:r['public_available_at'])
        for r in d.tables['canonical_facts']:
            f=payload(r)
            if f['doc_id']==docs[-1]['doc_id']:
                f.update(normalized_value=None,missing_reason='synthetic_null_update');r.update(pack(f))
        result=d.facts('edinet:'+docs[0]['edinet_code'],(datetime.fromisoformat(docs[-1]['public_available_at'])+timedelta(seconds=1)).isoformat())
        self.assertFalse(result['facts']);self.assertIn('synthetic_null_update',{r['reason'] for r in result['blocked']})

    def test_blocked_join_rows_are_not_dropped(self):
        rows=self.read_lines(self.p4/'pit_join_rows.jsonl');rows[0].update(status='BLOCKED',missing_reason='synthetic_blocked',normalized_value=None,price=None)
        self.write_lines(self.p4/'pit_join_rows.jsonl',rows);self.export();d=self.load()
        self.assertEqual(d.rows('pit_join_rows'),rows);self.assertEqual(d.rows('pit_join_rows')[0]['status'],'BLOCKED')

    def test_name_search_does_not_select_or_join_entities(self):
        self.export();d=self.load();original=d.rows('entities')[0];other=dict(original,entity_id='edinet:E99999',edinet_code='E99999')
        original['names']=['Synthetic Same Name'];other['names']=['Synthetic Same Name'];other['codes']=['99990']
        d.tables['entities']=[pack(original),pack(other)]
        self.assertEqual(len(d.company(name='Synthetic Same')),2)
        self.assertEqual(len(d.company(code='123A0')),1)
        self.assertEqual(d.facts('Synthetic Same Name',self.fact['public_available_at'])['blocked'][0]['reason'],'entity_not_in_snapshot')

    def test_mirror_cannot_be_promoted(self):
        self.export();d=self.load();c=payload(d.tables['derived_source_links'][0]);c['independent_evidence_increment']=1
        d.tables['derived_source_links'][0]=pack(c)
        with self.assertRaisesRegex(ContractError,'mirror_evidence_promoted'):validate_tables(d.tables)

    def test_orphan_and_removed_lineage_edge_rejected(self):
        self.export();d=self.load();edges=d.tables['lineage'];d.tables['lineage']=[]
        with self.assertRaisesRegex(ContractError,'required_lineage_edge_missing'):validate_tables(d.tables)
        d.tables['lineage']=edges+[pack({'from_table':'canonical_facts','from_id':'absent','to_table':'documents','to_id':self.fact['doc_id'],'relation':'bad'})]
        with self.assertRaisesRegex(ContractError,'orphan_lineage_edge'):validate_tables(d.tables)

    def test_git_checkout_and_input_export_boundary(self):
        git=self.base/'git';git.mkdir();(git/'.git').mkdir()
        for root in (git/'private',self.p3,self.p3/'nested',self.base):
            with self.subTest(root=root),self.assertRaises(ContractError):self.export(root=root)
        self.assertFalse((git/'private').exists())

    def test_current_cannot_escape_root(self):
        self.export();c=json.loads((self.root/'CURRENT.json').read_bytes());c['manifest']='../escape/manifest.json';self.write(self.root,'CURRENT.json',c)
        with self.assertRaisesRegex(ContractError,'current_pointer_mismatch'):self.load()
        for value in ('../secret','C:/secret','/secret','sub/../../secret','sub\\secret'):
            with self.assertRaises(ContractError):safe_path(self.root,value)

    def test_text_index_contains_hash_and_reference_not_body(self):
        self.export();d=self.load();row=d.rows('derived_source_rows')[0]
        self.assertIsNone(row['provider_fields']['text'])
        t=d.rows('text_index')[0]['texts']['text']
        self.assertEqual(t['text_sha256'],sha256(b'SYNTHETIC PRIVATE TEXT'))
        self.assertEqual(t['private_content_reference']['input_file'],'derived_observations.jsonl')

    def test_queries_never_write_package(self):
        self.export();before=snapshot_fingerprints(self.root);d=self.load()
        for command,args in [('company',{'code':'123A0'}),('filings',{'entity':'edinet:'+self.fact['edinet_code']}),
            ('joins',{'entity':'edinet:'+self.fact['edinet_code']}),('compare',{'doc_id':self.fact['doc_id']}),('failures',{})]:d.query(command,**args)
        self.assertEqual(before,snapshot_fingerprints(self.root))

    def test_system_replay_not_established(self):
        self.export();d=self.load();at=(datetime.fromisoformat(self.fact['public_available_at'])+timedelta(days=1)).isoformat()
        result=d.facts('edinet:'+self.fact['edinet_code'],at,'system_replay')
        self.assertFalse(result['facts']);self.assertTrue(result['blocked'])

    def test_duplicate_primary_id_rejected(self):
        self.export();d=self.load();d.tables['canonical_facts'].append(deepcopy(d.tables['canonical_facts'][0]))
        with self.assertRaisesRegex(ContractError,'duplicate_primary_key'):validate_tables(d.tables)

    def test_synthetic_fixture_not_accepted_as_private_real_data(self):
        self.export()
        with self.assertRaisesRegex(ContractError,'synthetic_not_empirical'):Dataset(self.root,codec=self.codec)


if __name__=='__main__':unittest.main()
