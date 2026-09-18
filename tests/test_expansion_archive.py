"""Synthetic cross-root lineage and immutable index regression tests."""
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from coverage_inventory import Inventory
from expansion_archive import build_index,CrossArchive
from evidence_core import ContractError
from source_acquisition import PrivateStore,encoded
from test_metadata_gap_audit import daily,row
from test_p2_audit import xml,zipped


class CrossArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.a=self.base/'a';self.b=self.base/'b'
        self.a.mkdir();self.b.mkdir()
        self.zip=self.a/'S0000001.zip';self.zip.write_bytes(zipped(xml()))
        self.meta=self.b/'list_2022-01-31.json';self.meta.write_bytes(daily([row(1)]))

    def build(self):
        plan={'snapshot_id':'synthetic','roots':[{'id':n,'source':'edinet_archive','kind':'edinet','path':str(p)} for n,p in [('a',self.a),('b',self.b)]]}
        with redirect_stdout(io.StringIO()):
            i=Inventory(plan,self.base/'inventory');i.observe_files()
            for r in plan['roots']:i.edinet(r)
            i.finish()
        build_index(i.output,self.base/'index')
        archive=CrossArchive(self.base/'index',PrivateStore(self.base/'audit'),provenance_class='synthetic_fixture')
        self.addCleanup(archive.close)
        return archive

    def series(self,archive):
        return archive.indexed_series({'challenge':['S0000001'],'probability':[]},{'S0000001':{'zip_files':[]}}, {'archive_root_id':archive.root_id},300)

    def test_cross_archive_metadata_original_and_source_roundtrip(self):
        a=self.build();inventory,plan,records=self.series(a)
        self.assertEqual(inventory['status'],'PASS')
        record=records['S0000001'];self.assertEqual(len(record['metadata_events']),1)
        artifact=a.observe(record['zip_files'][0]['relative_path'],doc_id='S0000001')
        self.assertEqual(a.read(artifact),self.zip.read_bytes())
        self.assertNotEqual(artifact['archive_root_id'],artifact['origin_artifact']['archive_root_id'])
        self.assertEqual(a.prove_unchanged()['status'],'PASS')

    def test_multistep_children_across_archives_and_missing_revision_zip(self):
        self.meta.write_bytes(daily([row(1),row(2,docTypeCode='130',parentDocID='S0000001'),row(3,docTypeCode='130',parentDocID='S0000002')]))
        a=self.build();_,plan,records=self.series(a)
        self.assertEqual(plan['revision_support'],['S0000002','S0000003'])
        self.assertEqual(records['S0000002']['zip_files'],[])

    def test_different_raw_versions_remain_ambiguous(self):
        (self.b/'S0000001.zip').write_bytes(b'different')
        a=self.build();self.assertEqual(len(self.series(a)[2]['S0000001']['zip_files']),2)

    def test_identical_raw_aliases_do_not_create_ambiguity(self):
        (self.b/'S0000001.zip').write_bytes(self.zip.read_bytes())
        a=self.build();self.assertEqual(len(self.series(a)[2]['S0000001']['zip_files']),1)

    def test_changed_raw_rejected_not_refreshed(self):
        a=self.build();self.zip.write_bytes(b'changed')
        with self.assertRaisesRegex(ContractError,'frozen_input_changed'):a.observe('a/S0000001.zip',doc_id='S0000001')

    def test_unregistered_path_and_traversal_rejected(self):
        a=self.build()
        with self.assertRaisesRegex(ContractError,'unregistered_cross_archive_locator'):a._bytes('../a/S0000001.zip')

    def test_rebuild_cannot_overwrite_existing_index(self):
        self.build()
        with self.assertRaisesRegex(ContractError,'snapshot_already_exists'):build_index(self.base/'inventory',self.base/'index')

    def test_metadata_entity_conflict_is_retained(self):
        data=json.loads(daily([row(1,edinetCode='E99999')]))
        data['metadata']['parameter']['date']='2022-02-01'
        (self.a/'list_2022-02-01.json').write_bytes(encoded(data))
        a=self.build();events=self.series(a)[2]['S0000001']['metadata_events']
        self.assertEqual({e['provider_fields']['edinetCode'] for e in events},{'E00001','E99999'})

    def test_identity_conflicts_outside_current_partition_are_re_read(self):
        self.meta.write_bytes(daily([row(1,secCode='12340'),row(2,edinetCode='E99999',secCode='12340')]))
        a=self.build()
        peers=a.identity_peers([{'doc_id':'S0000001','edinet_code':'E00001','secCode':'12340'}],synthetic=True)
        self.assertEqual(len(peers),1);self.assertEqual(peers[0]['edinet_code'],'E99999')
        self.assertEqual(peers[0]['status'],'PASS')
        self.meta.write_bytes(b'changed')
        with self.assertRaisesRegex(ContractError,'frozen_input_changed'):
            a.identity_peers([{'doc_id':'S0000001','edinet_code':'E00001','secCode':'12340'}],synthetic=True)


if __name__=='__main__':unittest.main()
