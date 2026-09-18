"""Offline synthetic federation; providers and secrets are never read."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import gzip
from pathlib import Path
import unittest
import zipfile

from evidence_core import ContractError
from expansion_runner import reconstructable_files,replay_stage_file
from partitioned_dataset import publish_federation,PartitionedDataset,merge_entity,coverage_records,binary_key,write_expansion_coverage
from source_acquisition import encoded,sha256
import test_dataset_package as fixtures


class PartitionedDatasetTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.DatasetPackageTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        self.root=f.base/'federation';self.root.mkdir();self.job=self.root/'jobs/one';self.job.mkdir(parents=True)
        self.plan={'created_at':'2026-09-19T00:00:00+00:00','jobs':[{'job_id':'one','month':'2022-06','doc_ids':['S0000001']}],
                   'blocked_documents':[]}

    def build(self):
        self.f.export(root=self.job/'package')
        with zipfile.ZipFile(self.job/'evidence.zip','x') as z:z.writestr('synthetic.json',b'{}')
        raw=encoded(self.plan);(self.root/'expansion_plan.json').write_bytes(raw)
        for job in self.plan['jobs']:
            folder=self.root/'jobs'/job['job_id'];folder.mkdir(parents=True,exist_ok=True)
            r={'plan_sha256':sha256(raw),'status':'COMPLETE' if job['job_id']=='one' else 'BLOCKED','reason':'synthetic_block',
               'artifacts':{p.relative_to(folder).as_posix():sha256(p.read_bytes()) for p in folder.rglob('*') if p.is_file()}}
            (folder/'result.json').write_bytes(encoded(r))
        return publish_federation(self.root,'synthetic-final',codec=self.f.codec,synthetic=True)

    def load(self):
        d=PartitionedDataset(self.root,codec=self.f.codec,allow_synthetic=True);self.addCleanup(d.close);return d

    def test_query_and_lineage_route_without_promoting_mirror(self):
        s=self.build();d=self.load();f=self.f.fact
        self.assertEqual(s['complete_partitions'],1)
        self.assertEqual(d.query('company',entity='edinet:'+f['edinet_code'])['rows'][0]['edinet_code'],f['edinet_code'])
        trace=d.query('lineage',fact_id=f['fact_id'])
        self.assertEqual(len(trace['occurrences']),1);self.assertEqual(trace['independent_evidence_increment'],0)
        nodes=trace['occurrences'][0]['lineage']['nodes']
        self.assertIn('original_locators',{n['table'] for n in nodes})
        self.assertEqual(d.query('validate')['status'],'PASS')
        self.assertFalse(s['export_allowed']);self.assertEqual(s['rights_status'],'BLOCKED')

    def test_blocked_jobs_retained_in_snapshot(self):
        self.plan['jobs'].append({'job_id':'two','month':'2025-01','doc_ids':['S0000999']})
        s=self.build();self.assertEqual(s['blocked_partitions'],1)
        ledger=(self.root/'snapshots/synthetic-final/gap_ledger.jsonl').read_bytes()
        self.assertIn(b'synthetic_block',ledger)

    def test_index_corruption_rejected(self):
        self.build();p=self.root/'snapshots/synthetic-final/locator.sqlite';p.write_bytes(p.read_bytes()+b'changed')
        with self.assertRaisesRegex(ContractError,'federation_artifact_changed'):self.load()

    def test_entity_merge_is_identifier_only(self):
        e={'entity_id':'edinet:E00001','edinet_code':'E00001','names':['Same'],'codes':['12340'],'document_ids':['a'],'name_evidence':[]}
        other=dict(e,names=['New'],codes=['12A40'],document_ids=['b'])
        self.assertEqual(merge_entity(e,other)['document_ids'],['a','b'])
        with self.assertRaisesRegex(ContractError,'entity_identifier_conflict'):merge_entity(e,dict(other,edinet_code='E00002'))

    def test_no_original_or_no_completed_job_stays_blocked(self):
        docs=[{'doc_id':'a','originals':[]},{'doc_id':'b','originals':[{}]},{'doc_id':'c','originals':[{}]}]
        state={'c':{'source_tied_facts':1,'canonical_eligible_facts':0,'pit_pass':0}}
        a,b,c=list(coverage_records(docs,state))
        self.assertIn('official_original_not_available',a['missing_reasons'])
        self.assertIn('partition_not_completed',b['missing_reasons'])
        self.assertEqual(c['source_tied'],'PASS');self.assertEqual(c['canonical_eligible'],'BLOCKED')
        self.assertEqual(c['pit_eligible'],'BLOCKED');self.assertEqual(c['research_ready'],'BLOCKED')

    def test_index_key_keeps_hex_and_text_namespaces_distinct(self):
        self.assertNotEqual(binary_key('a'*32),binary_key(('a'*32).encode().hex()))

    def test_empirical_publication_requires_completed_gates(self):
        (self.root/'expansion_plan.json').write_bytes(encoded(self.plan))
        with self.assertRaisesRegex(ContractError,'final_acceptance_gate_missing'):publish_federation(self.root,'final')
        self.assertFalse((self.root/'CURRENT.json').exists())

    def test_full_coverage_keeps_unknown_and_checks_missing_cache(self):
        inv=self.root/'inventory';inv.mkdir();out=self.root/'reports';out.mkdir();idx=self.root/'index';idx.mkdir()
        docs=[{'doc_id':'a','originals':[{}],'submit_date':'2022-06-01','document_types':['120']},
              {'doc_id':'b','originals':[],'submit_date':None,'document_types':[]}]
        (inv/'document_coverage.jsonl').write_bytes(b''.join(encoded(d)+b'\n' for d in docs))
        base={'month':'2022-06','status':'READY','input_artifacts':[{'root_id':'r','relative_path':'synthetic','byte_sha256':'0'*64}]}
        queue=[dict(base,source='edinet_original',table='ZIP:120'),dict(base,source='jquants',table='equities_master'),
               dict(base,source='numad',table='text_blocks',status='UNKNOWN',input_artifacts=[])]
        (inv/'expansion_queue.jsonl').write_bytes(b''.join(encoded(r)+b'\n' for r in queue))
        (idx/'cross_archive_index.json').write_bytes(encoded({'failures':[]}))
        state={'a':{'source_tied_facts':1,'canonical_eligible_facts':0,'pit_pass':0}}
        summary=write_expansion_coverage({'inventory':str(inv),'archive_index':str(idx),'row_cache':str(self.root/'absent')},out,state,
            [{'job_id':'one','doc_ids':['a'],'status':'COMPLETE'}])
        self.assertIn('unknown',summary['year_document_states'])
        with gzip.open(out/'expansion_queue.jsonl.gz','rt') as f:observed=[json.loads(x) for x in f]
        self.assertEqual(observed[0]['status'],'COMPLETE')
        self.assertEqual(observed[1]['reason'],'jquants_row_cache_missing_or_failed')
        self.assertEqual(observed[2]['prior_status'],'UNKNOWN');self.assertEqual(observed[2]['status'],'BLOCKED')
        profiles=json.loads((out/'coverage_artifact_profiles.json').read_bytes())
        self.assertEqual(profiles['document_coverage.jsonl.gz']['row_count'],2)

    def test_exact_stage_file_reconstruction(self):
        # Name the source directories exactly as the snapshot reference specifies.
        import shutil
        self.f.export(root=self.job/'package')
        work=self.f.base/'reconstruction';work.mkdir()
        for path in (self.f.p3,self.f.p4,self.f.p5):
            snapshot=json.loads((path/'audit_plan.json').read_bytes())['snapshot_id']
            shutil.copytree(path,work/snapshot)
        reusable=reconstructable_files(work,self.job/'package',codec=self.f.codec,synthetic=True)
        targets=[(n,r) for n,r in reusable.items() if n.endswith('/canonical_facts.jsonl')]
        self.assertEqual(len(targets),1)
        name,description=targets[0]
        self.assertEqual(replay_stage_file(self.job/'package',description,codec=self.f.codec,synthetic=True),(work/name).read_bytes())
        bad=dict(description,sha256='0'*64)
        with self.assertRaisesRegex(ContractError,'reconstruction_hash_failed'):replay_stage_file(self.job/'package',bad,codec=self.f.codec,synthetic=True)


if __name__=='__main__':unittest.main()
