"""Read-only CSV/manifest and private P4 output tests using generated synthetic files."""
from contextlib import redirect_stdout
from copy import deepcopy
import csv
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest

from evidence_core import ContractError
from jquants_local import JQuantsArchive, DATASETS, csv_rows
from metadata_gap_audit import snapshot_fingerprints
from p4_audit import run
from source_acquisition import PrivateStore, encoded, sha256
import test_p3_audit as p3_fixture


def write_source(root, dataset, rows):
    folder = root / dataset / 'revision=synthetic'; folder.mkdir(parents=True)
    text = io.StringIO(newline=''); writer = csv.DictWriter(text,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    raw = gzip.compress(text.getvalue().encode(),mtime=0)
    path = folder / 'synthetic.csv.gz';path.write_bytes(raw)
    field = 'DiscDate' if dataset == 'fins_summary' else 'Date'
    days = sorted(r[field] for r in rows)
    f={'file':path.name,'sha256':sha256(raw),'bytes':len(raw),'minimum_date':days[0],'maximum_date':days[-1]}
    (folder/'manifest.json').write_bytes(encoded({'schema_version':1,'dataset':dataset,'revision':'synthetic',
        'minimum_date':days[0],'maximum_date':days[-1],'files':[f]}))
    return path


class JQuantsLocalTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.base=Path(t.name)
        self.root=self.base/'input';self.root.mkdir()
        for dataset in DATASETS:
            if dataset=='markets_calendar': row={'Date':'2022-06-01','HolDiv':'1'}
            elif dataset=='equities_master': row={'Date':'2022-06-01','Code':'123A0','Mkt':'0111','ProdCat':'synthetic','CoName':'DO NOT JOIN BY NAME'}
            elif dataset=='equities_bars_daily': row={'Date':'2022-06-01','Code':'123A0','O':'1','H':'2','L':'1','C':'2','Vo':'3','AdjFactor':'0.5'}
            else: row={'DiscDate':'2022-06-01','DiscTime':'15:00:00','Code':'123A0','DiscNo':'synthetic','DocType':'FYFinancialStatements_Consolidated_JP','CurPerSt':'2021-04-01','CurPerEn':'2022-03-31'}
            write_source(self.root,dataset,[row])
        self.archive=JQuantsArchive(self.root,PrivateStore(self.base/'audit'),synthetic=True)
        self.windows={d:[('2022-01-01','2022-12-31')] for d in DATASETS if d!='markets_calendar'}

    def test_actual_bytes_schema_counts_locator_and_missing_acquisition_metadata(self):
        before=snapshot_fingerprints(self.root); plan=self.archive.plan(self.windows)
        profile,rows=self.archive.inspect(plan['files'][0],lambda r:True)
        self.assertEqual(profile['row_count'],1);self.assertEqual(profile['artifact']['byte_count'],plan['files'][0]['expected_bytes'])
        self.assertIsNone(profile['artifact']['original_provider_retrieved_at']);self.assertIsNone(profile['artifact']['provider_version'])
        self.assertEqual(self.archive.verify_rows(rows)['status'],'PASS')
        self.assertEqual(before,snapshot_fingerprints(self.root))

    def test_hash_mismatch_rejected_before_parsing(self):
        f=self.archive.plan(self.windows)['files'][0];f['expected_sha256']='0'*64
        with self.assertRaisesRegex(ContractError,'jquants_byte_integrity_failed'): self.archive.inspect(f,lambda r:True)

    def test_missing_hash_is_not_integrity_success(self):
        f=self.archive.plan(self.windows)['files'][0];f['expected_sha256']=None
        with self.assertRaisesRegex(ContractError,'source_manifest_integrity_missing'): self.archive.inspect(f,lambda r:True)

    def test_corrupt_gzip_bad_header_and_row_width(self):
        for raw,compressed in ((b'bad',True),(b'a,a\n1,2\n',False),(b'a,b\n1\n',False)):
            with self.assertRaises(ContractError): list(csv_rows(raw,compressed))

    def test_changed_row_or_source_locator_cannot_reverse_verify(self):
        _,rows=self.archive.inspect(self.archive.plan(self.windows)['files'][0],lambda r:True)
        for mutate in (lambda r:r['provider_fields'].update(Code='99990'),lambda r:r['source'].update(record_index=999)):
            tampered=deepcopy(rows);mutate(tampered[0])
            with self.assertRaises(ContractError):self.archive.verify_rows(tampered)

    def test_multiple_local_revisions_are_not_implicitly_latest(self):
        d=self.root/'equities_master/revision=other';d.mkdir();(d/'manifest.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ContractError,'manifest_missing_or_ambiguous'):self.archive.plan(self.windows)

    def test_archive_inside_git_and_output_inside_source_are_rejected(self):
        (self.root/'.git').mkdir()
        with self.assertRaises(ContractError):JQuantsArchive(self.root,PrivateStore(self.base/'other'))


class P4OutputTests(unittest.TestCase):
    def setUp(self):
        p3_fixture.P3AuditTests.setUp(self)
        # P3 itself creates and verifies a completely synthetic snapshot.
        p3_fixture.P3AuditTests.audit(self)
        self.p3=self.base/'output/synthetic-p3';self.jq=self.base/'jquants';self.jq.mkdir()
        for dataset in DATASETS:
            if dataset=='markets_calendar':
                rows=[{'Date':f'2022-06-{d:02d}','HolDiv':'0' if d in (4,5) else '1'} for d in range(1,8)]
            elif dataset=='equities_master': rows=[{'Date':'2022-06-01','Code':'123A0','Mkt':'0111','ProdCat':'synthetic'}]
            elif dataset=='equities_bars_daily': rows=[{'Date':'2022-05-31','Code':'123A0','O':'1','H':'2','L':'1','C':'2','Vo':'3','AdjFactor':'1'}]
            else: rows=[{'DiscDate':'2022-05-01','DiscTime':'15:00:00','Code':'123A0','DiscNo':'synthetic',
                'DocType':'FYFinancialStatements_Consolidated_JP','CurPerType':'FY','CurPerSt':'2021-04-01','CurPerEn':'2022-03-31','Sales':'1'}]
            write_source(self.jq,dataset,rows)

    def audit(self):
        with redirect_stdout(io.StringIO()): return run(self.jq,self.root,self.p3,self.base/'p4','synthetic-p4',synthetic=True)

    def test_all_private_outputs_and_input_preservation_with_realistic_missing_identity(self):
        before={p:snapshot_fingerprints(p) for p in (self.jq,self.root,self.p3)}
        summary=self.audit();self.assertEqual(summary['empirical_pit_join'],'BLOCKED')
        self.assertEqual(summary['complete_pit_joins'],0)
        self.assertIn('calendar_vintage_not_established',summary['failure_counts'])
        self.assertEqual(before,{p:snapshot_fingerprints(p) for p in before})
        folder=self.base/'p4/synthetic-p4'
        for name in ('jquants_inventory.json','security_identity_map.jsonl','trading_calendar.jsonl','market_observations.jsonl',
                     'pit_join_rows.jsonl','cross_source_reconciliation.jsonl','lineage.jsonl','failure_ledger.jsonl','coverage_summary.json','preservation_proof.json'):
            self.assertTrue((folder/name).is_file(),name)
        for r in map(json.loads,(folder/'pit_join_rows.jsonl').read_bytes().splitlines()):
            self.assertEqual(r['snapshot_id'],'synthetic-p4');self.assertTrue(r['synthetic']);self.assertFalse(r['export_allowed'])
            self.assertIsNone(r['normalized_value'])

    def test_public_checkout_and_existing_snapshot_outputs_are_rejected(self):
        repo=self.base/'public';repo.mkdir();(repo/'.git').mkdir()
        with self.assertRaises(ContractError):run(self.jq,self.root,self.p3,repo,'bad',synthetic=True)
        self.assertFalse((repo/'bad').exists())
        self.audit()
        with self.assertRaisesRegex(ContractError,'snapshot_already_exists'):self.audit()


if __name__ == '__main__': unittest.main()
