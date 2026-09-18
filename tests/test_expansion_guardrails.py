"""Synthetic output boundaries and fresh input checks on checkpoint reuse."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from evidence_core import ContractError
from source_acquisition import encoded,sha256
from expansion_runner import plan_expansion,run,code_identity
from expansion_sources import indexed_bundle
from p3_audit import run as p3
from p4_audit import run as p4
from p5_audit import run as p5


class ExpansionGuardTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.base=Path(tmp.name).resolve()
        for name in ('raw','prior','jquants','index','derived','bundle','inventory'):
            setattr(self,name,self.base/name);getattr(self,name).mkdir()
        (self.index/'cross_archive_index.json').write_bytes(encoded({'roots':{'original':str(self.raw)}}))
        (self.derived/'manifest.json').write_bytes(encoded({'source_root':str(self.bundle)}))
        (self.inventory/'inventory_plan.json').write_bytes(encoded({'plan':{'roots':[{'id':'raw','path':str(self.raw)}]}}))

    def test_all_stages_reject_transitive_raw_output_before_mkdir(self):
        output=self.raw/'forbidden'
        calls=[lambda:p3(self.index,self.prior,self.raw,'forbidden'),
               lambda:p4(self.jquants,self.index,self.prior,self.raw,'forbidden'),
               lambda:p5(self.index,self.prior,self.bundle,self.raw,'forbidden')]
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaisesRegex(ContractError,'output_inside_input'):call()
                self.assertFalse(output.exists())

    def test_plan_rejects_input_and_cache_overlap_before_mkdir(self):
        output=self.raw/'forbidden'
        with self.assertRaisesRegex(ContractError,'plan_input_overlap'):
            plan_expansion(self.inventory,self.index,self.derived,self.jquants,output)
        self.assertFalse(output.exists())
        output=self.base/'plan'
        with self.assertRaisesRegex(ContractError,'cache_overlaps_source'):
            plan_expansion(self.inventory,self.index,self.derived,self.jquants,output,row_cache=self.raw/'cache')
        self.assertFalse(output.exists());self.assertFalse((self.raw/'cache').exists())

    def test_shared_derived_raw_and_market_cache_are_protected(self):
        output=self.bundle/'forbidden'
        with self.assertRaisesRegex(ContractError,'bundle_output_overlap'):
            indexed_bundle(self.derived,self.prior,['S0000001'],output)
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(ContractError,'output_inside_input'):
            p5(self.index,self.prior,self.base/'unused-input',self.bundle,'forbidden',raw_store=self.bundle)
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(ContractError,'cache_overlaps_source'):
            p4(self.jquants,self.index,self.prior,self.base,'output',row_cache=self.raw/'cache')
        self.assertFalse((self.base/'output').exists());self.assertFalse((self.raw/'cache').exists())

    def completed_plan(self):
        source=self.raw/'synthetic.bin';source.write_bytes(b'synthetic')
        catalog=encoded({'root_id':'raw','relative_path':source.name,'byte_sha256':sha256(source.read_bytes()),
                         'byte_count':source.stat().st_size,'mtime_ns':source.stat().st_mtime_ns})+b'\n'
        (self.inventory/'source_files.jsonl').write_bytes(catalog)
        root=self.base/'expansion';root.mkdir();folder=root/'jobs/one';folder.mkdir(parents=True)
        plan={'code_files':code_identity(),'archive_index':str(self.index),'derived_index':str(self.derived),
              'archive_manifest_sha256':sha256((self.index/'cross_archive_index.json').read_bytes()),
              'derived_manifest_sha256':sha256((self.derived/'manifest.json').read_bytes()),
              'inventory':str(self.inventory),'input_hashes':{'source_files.jsonl':sha256(catalog)},
              'jobs':[{'job_id':'one'}]}
        raw=encoded(plan);(root/'expansion_plan.json').write_bytes(raw)
        checkpoint=encoded({'job_id':'one','plan_sha256':sha256(raw),'status':'COMPLETE','artifacts':{}})
        (folder/'result.json').write_bytes(checkpoint)
        return root,source,folder/'result.json',checkpoint

    def test_checkpoint_reuse_rehashes_raw_and_preserves_checkpoint_bytes(self):
        root,source,checkpoint,before=self.completed_plan()
        with redirect_stdout(io.StringIO()):self.assertEqual(run(root),{'COMPLETE':1})
        self.assertEqual(checkpoint.read_bytes(),before)
        proof=json.loads(next((root/'input-checks').glob('*.json')).read_bytes())
        self.assertEqual(proof['files_rehashed'],1)
        source.write_bytes(b'changed!!')
        with self.assertRaisesRegex(ContractError,'input_bytes_changed'):run(root)
        self.assertEqual(checkpoint.read_bytes(),before)

    def test_checkpoint_reuse_rejects_extra_original_file(self):
        root,source,checkpoint,before=self.completed_plan()
        (self.raw/'unexpected').write_bytes(b'extra')
        with self.assertRaisesRegex(ContractError,'input_file_set_changed'):run(root)
        self.assertFalse((root/'input-checks').exists())
        self.assertEqual(checkpoint.read_bytes(),before)

    def test_different_code_can_verify_completed_bytes_but_cannot_execute(self):
        root,source,checkpoint,before=self.completed_plan()
        path=root/'expansion_plan.json';plan=json.loads(path.read_bytes());plan['code_files']={'recorded_engine.py':'0'*64}
        raw=encoded(plan);path.write_bytes(raw)
        result=json.loads(before);result['plan_sha256']=sha256(raw);checkpoint.write_bytes(encoded(result))
        with self.assertRaisesRegex(ContractError,'execution_code_changed_since_plan'):run(root)
        with redirect_stdout(io.StringIO()):self.assertEqual(run(root,verify_only=True),{'COMPLETE':1})
        self.assertEqual(json.loads(checkpoint.read_bytes()),result)

    def test_verify_only_never_executes_missing_partition(self):
        root,source,checkpoint,before=self.completed_plan();checkpoint.unlink()
        with self.assertRaisesRegex(ContractError,'unfinished_expansion_job'):run(root,verify_only=True)
        self.assertFalse(checkpoint.exists())


if __name__=='__main__':unittest.main()
