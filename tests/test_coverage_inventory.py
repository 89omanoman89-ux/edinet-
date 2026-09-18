"""P5.6 synthetic-only inventory and fixed selection tests; no local user data."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from coverage_inventory import Inventory, day, file_hash, freeze_selection, partitions
from coverage_replay import execute_sample, frame_for, verify_partition
from evidence_core import ContractError
from source_acquisition import encoded, sha256
from test_metadata_gap_audit import daily, row
from test_p2_audit import xml, zipped


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base/'raw'; (self.root/'documents').mkdir(parents=True)
        self.zip = self.root/'documents/S0000001.zip'; self.zip.write_bytes(zipped(xml()))
        self.meta = self.root/'listings/2022-01-31/documents.json'
        self.meta.parent.mkdir(parents=True); self.meta.write_bytes(daily([row(1, secCode='123A0')]))
        self.spec = {'id':'raw', 'source':'edinet_archive', 'kind':'edinet', 'path':str(self.root)}
        self.plan = {'snapshot_id':'synthetic-coverage', 'roots':[self.spec]}

    def inventory(self):
        obj = Inventory(self.plan, self.base/'out')
        with redirect_stdout(io.StringIO()): obj.observe_files(); obj.edinet(self.spec)
        return obj

    def test_dates_are_not_inferred_from_names_or_period_year(self):
        self.assertIsNone(day('file-2022-01.csv')); self.assertIsNone(day('2022-02-30'))
        self.assertEqual(day('2022-02-01 15:00'), '2022-02-01')

    def test_actual_rows_hash_and_string_security(self):
        i = self.inventory(); docs = i.finalize_documents()
        self.assertEqual(len(docs), 1); self.assertEqual(docs[0]['securities'], ['123A0'])
        self.assertEqual(docs[0]['originals'][0]['byte_sha256'], file_hash(self.zip))
        self.assertEqual(i.artifact('raw','listings/2022-01-31/documents.json')['rows'], 1)

    def test_existence_never_promotes_tie_canonical_pit_or_rights(self):
        d = self.inventory().finalize_documents()[0]
        self.assertEqual(d['data_exists'], 'PASS')
        for k in ('source_tied','canonical_eligible','pit_eligible','research_ready'):
            self.assertEqual(d[k], 'BLOCKED')

    def test_duplicate_doc_ids_keep_multiple_byte_versions_and_block_reason(self):
        other = self.root/'documents/sub/S0000001.zip'; other.parent.mkdir(); other.write_bytes(b'corrupt')
        d = self.inventory().finalize_documents()[0]
        self.assertEqual(len(d['originals']), 2)
        self.assertIn('original_bytes_ambiguous', d['missing_reasons'])

    def test_missing_metadata_does_not_invent_date(self):
        self.meta.unlink(); d = self.inventory().finalize_documents()[0]
        self.assertEqual(d['submit_date'], '')
        self.assertIn('official_metadata_not_available', d['missing_reasons'])

    def test_derived_only_never_official_original(self):
        i = self.inventory(); i.document('S0000002')['sources'].add('numad')
        d = i.finalize_documents()[1]
        self.assertFalse(d['official_original_available'])

    def test_corrupt_daily_is_not_silently_ignored(self):
        self.meta.write_bytes(b'{}'); i = self.inventory()
        self.assertEqual(i.gaps[0]['reason'], 'daily_metadata_schema_rejected')

    def test_fixed_seed_selection_stable_when_input_order_changes(self):
        docs = self.inventory().finalize_documents()
        docs += [dict(docs[0], doc_id='S0000002')]
        self.assertEqual(freeze_selection(docs), freeze_selection(list(reversed(docs))))

    def test_selection_ignores_downstream_outcomes_and_keeps_unavailable_years(self):
        docs = self.inventory().finalize_documents(); before = freeze_selection(docs)
        docs[0]['pit_eligible'] = 'BLOCKED'; docs[0]['source_tied'] = 'BLOCKED'
        self.assertEqual(before, freeze_selection(docs))
        self.assertEqual(len(before), 11)
        self.assertEqual(before[0]['reason'], 'annual_original_not_available')

    def test_all_132_months_and_unknown_future_partitions(self):
        q = partitions([], [], '2026-09-18')
        jq = [p for p in q if p['source']=='jquants' and p['table']=='equities_master']
        self.assertEqual(len(jq), 132)
        self.assertEqual(jq[-1]['status'], 'UNKNOWN')
        self.assertIsNone(jq[0]['estimated_rows'])

    def test_outputs_and_inputs_preserved_with_hash_proof(self):
        i = self.inventory(); before = file_hash(self.zip)
        with redirect_stdout(io.StringIO()): i.finish()
        self.assertEqual(before, file_hash(self.zip))
        proof = json.loads((i.output/'preservation_proof.json').read_bytes())
        self.assertEqual(proof['status'], 'PASS')
        for name in ('source_files','date_coverage','document_coverage','overlap_matrix','gap_ledger','expansion_queue'):
            self.assertTrue((i.output/(name+'.jsonl')).is_file())

    def test_modified_input_or_current_is_rejected(self):
        current = self.root/'CURRENT.json'; current.write_bytes(b'old')
        i = self.inventory(); i.lines('source_files.jsonl', i.files)
        current.write_bytes(b'new')
        with self.assertRaisesRegex(ContractError, 'input_bytes_changed'): i.preserve()

    def test_added_input_is_rejected(self):
        i = self.inventory(); (self.root/'new').write_bytes(b'new')
        with self.assertRaisesRegex(ContractError, 'input_file_set_changed'): i.preserve()

    def test_git_destination_and_input_overlap_rejected(self):
        git = self.base/'git'; (git/'.git').mkdir(parents=True)
        with self.assertRaises(ContractError): Inventory(self.plan, git/'output')
        with self.assertRaises(ContractError): Inventory(self.plan, self.root/'output')
        self.assertFalse((git/'output').exists())

    def test_old_snapshot_never_overwritten(self):
        self.inventory()
        with self.assertRaisesRegex(ContractError, 'snapshot_already_exists'): self.inventory()

    def test_ready_partition_inputs_reverified(self):
        i = self.inventory()
        with redirect_stdout(io.StringIO()): i.finish()
        q = [json.loads(x) for x in (i.output/'expansion_queue.jsonl').read_bytes().splitlines()]
        p = next(x for x in q if x['source']=='edinet_original' and x['status']=='READY')
        self.assertEqual(verify_partition(i.output, p['partition_id'])['partition_id'], p['partition_id'])
        self.zip.write_bytes(b'changed')
        with self.assertRaisesRegex(ContractError, 'partition_input_changed'): verify_partition(i.output, p['partition_id'])

    def test_frame_checks_frozen_hash_before_p3(self):
        i = self.inventory(); s = next(x for x in freeze_selection(i.finalize_documents()) if x['status']=='SELECTED')
        self.zip.write_bytes(b'changed')
        with self.assertRaisesRegex(ContractError, 'frozen_original_changed'):
            frame_for(s, {'raw': str(self.root)}, self.base/'frame')

    def test_failed_year_not_replaced_or_run(self):
        s = freeze_selection([])[0]
        result = execute_sample(s, {}, 'unused', 'unused', self.base/'replay', synthetic=True)
        self.assertEqual(result['overall'], 'BLOCKED'); self.assertEqual(result['p3'], 'NOT RUN')
        self.assertIsNone(result['doc_id'])

    def test_numad_prefix_counts_complete_actual_rows_not_claim(self):
        bundle = self.base/'bundle'; (bundle/'raw').mkdir(parents=True)
        raw = encoded({'doc_id':'S0000002','submit_date':'2022-02-01','text':'SYNTHETIC'})+b'\n{"incomplete":'
        digest=sha256(raw); (bundle/'raw'/digest).write_bytes(raw)
        asset={'source_id':'numad','table':'text_blocks','asset_id':'synthetic', 'file_row_count':999999,
               'evidence':{'scope':'prefix','artifacts':[{'byte_sha256':digest,'byte_count':len(raw)}]}}
        (bundle/'bundle.json').write_bytes(encoded({'assets':[asset]}))
        spec={'id':'bundle','source':'derived_inputs','kind':'derived_bundle','path':str(bundle)}
        self.plan['roots'].append(spec)
        i=self.inventory()
        with redirect_stdout(io.StringIO()): i.derived(spec)
        g=i.groups[('numad','text_blocks','submit_date','2022-02')]
        self.assertEqual(g['rows'],1)
        self.assertEqual(i.gaps[-1]['remote_row_count_claim'],999999)
        self.assertEqual(i.gaps[-1]['decoded_rows'],1)
        self.assertFalse(i.finalize_documents()[1]['official_original_available'])

    def test_unknown_date_rows_are_retained_in_queue(self):
        f={'file_id':'f','byte_sha256':'a'*64,'byte_count':1,'root_id':'r','relative_path':'f'}
        c={'source':'numad','table':'text_blocks','month':'unknown','rows':2,'input_artifacts':['f']}
        q=partitions([c],[f],'2026-09-18')
        unknown=next(p for p in q if p['month']=='unknown')
        self.assertEqual(unknown['estimated_rows'],2);self.assertEqual(unknown['status'],'UNKNOWN')

    def test_partial_csv_never_ready(self):
        f={'file_id':'f','byte_sha256':'a'*64,'byte_count':1,'root_id':'r','relative_path':'f',
           'row_count_basis':'partial_before_parse_failure'}
        c={'source':'jquants','table':'equities_master','month':'2022-01','rows':2,'input_artifacts':['f']}
        q=partitions([c],[f],'2026-09-18')
        target=next(p for p in q if p['source']=='jquants' and p['table']=='equities_master' and p['month']=='2022-01')
        self.assertEqual(target['status'],'BLOCKED')

    def test_hash_checkpoint_is_verified_and_rehashed_before_pass(self):
        old=self.inventory()
        checkpoint=old.output/'file_hash_checkpoint.jsonl'
        plan=dict(self.plan,hash_checkpoint=str(checkpoint),hash_checkpoint_sha256=file_hash(checkpoint))
        new=Inventory(plan,self.base/'resumed')
        with redirect_stdout(io.StringIO()):new.observe_files();new.edinet(self.spec);new.finish()
        self.assertTrue(all(r['hash_checkpoint_reused'] for r in new.files))
        proof=json.loads((new.output/'preservation_proof.json').read_bytes())
        self.assertEqual(proof['files_rehashed'],len(new.files))

    def test_cross_year_failure_never_calls_next_stage(self):
        from unittest.mock import patch
        i=self.inventory();s=next(r for r in freeze_selection(i.finalize_documents()) if r['status']=='SELECTED')
        with patch('p3_audit.run',side_effect=ContractError('synthetic_revision_branch')),patch('p4_audit.run') as p4:
            r=execute_sample(s,{'raw':str(self.root)},'unused','unused',self.base/'replay',synthetic=True)
        self.assertEqual(r['reason'],'synthetic_revision_branch');self.assertEqual(r['doc_id'],s['doc_id'])
        p4.assert_not_called()

    def test_prior_source_tie_requires_matching_current_original_hash(self):
        root=self.base/'p5'; accepted=root/'accepted';accepted.mkdir(parents=True)
        artifact=accepted/'original_artifacts.jsonl'
        artifact.write_bytes(encoded({'doc_id':'S0000001','artifact':{'byte_sha256':file_hash(self.zip)}})+b'\n')
        (accepted/'comparison_ledger.jsonl').write_bytes(encoded({'doc_id':'S0000001','source_id':'queria',
            'status':'PASS','origin_ids':['synthetic-original'],'public_available_at':'2022-01-31T15:00:00+09:00'})+b'\n')
        spec={'id':'p5','source':'p5','kind':'snapshots','path':str(root),'accepted_snapshot':'accepted'}
        self.plan['roots'].append(spec); i=self.inventory();i.snapshots(spec)
        self.assertEqual(i.prior_acceptance['queria']['source_tied_comparison_rows'],1)
        i.prior_acceptance.clear();self.zip.write_bytes(b'changed')
        i.docs['S0000001']['originals'][0]['byte_sha256']=file_hash(self.zip)
        i.snapshots(spec)
        self.assertEqual(i.prior_acceptance['queria']['source_tied_comparison_rows'],0)

    def test_dated_daily_filename_recognized_and_manifest_excluded(self):
        self.meta.rename(self.meta.with_name('list_2022-01-31.json'))
        self.meta.with_name('list_2022-01-31.manifest.json').write_bytes(b'{}')
        i=self.inventory();d=i.finalize_documents()[0]
        self.assertEqual(d['submit_date'],'2022-01-31');self.assertFalse(i.gaps)

    def test_flat_archive_layout_copy_preserves_original_bytes(self):
        flat=self.base/'flat';flat.mkdir()
        z=flat/'S0000001.zip';z.write_bytes(self.zip.read_bytes())
        m=flat/'list_2022-01-31.json';m.write_bytes(self.meta.read_bytes())
        self.spec['path']=str(flat);i=self.inventory();before={p.name:file_hash(p) for p in flat.iterdir()}
        selected=next(r for r in freeze_selection(i.finalize_documents()) if r['status']=='SELECTED')
        root=frame_for(selected,{'raw':str(flat)},self.base/'new/frame',frozen_files=i.files)
        self.assertEqual(before,{p.name:file_hash(p) for p in flat.iterdir()})
        self.assertEqual(file_hash(root/'documents/S0000001.zip'),file_hash(z))
        self.assertEqual(file_hash(root/'listings/list_2022-01-31.json'),file_hash(m))
        self.assertTrue((root/'origin_map.json').is_file())


if __name__ == '__main__': unittest.main()
