"""P5 synthetic bytes only. No provider packages, network, secrets or private paths."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from derived_sources import (original_index, document_link, compare_fact, compare_context, compare_relation,
                             mart_components, scalar_equal, DEFINITION)
from evidence_core import ContractError
from p5_acquisition import fetch,RangeFile,tar_index
from p5_audit import run,verify_source_rows,RecordedRanges
from source_acquisition import PrivateStore,encoded,sha256
from metadata_gap_audit import snapshot_fingerprints
import test_p3_audit as p3_fixture
from test_financial_facts import instance,archive,document,extract,JP,CRP


def indexed(xml=None,extra=None):
    raw,a,d,_,_=extract(xml,extra=extra);return original_index(raw,a,d)


def numeric(**changes):
    r={'doc_id':'S0000001','concept':'{'+JP+'}NetSales','context_id':'CurrentYearDuration','unit_ref':'yen',
       'value_type':'decimal','value_numeric':'123000000','value_text':None,'is_nil':False,
       'period_type':'duration','period_start':'2021-04-01','period_end':'2022-03-31','period_instant':None,
       'entity_id':'E00001-000','dimensions_json':None}
    return dict(r,**changes)


class DerivedComparisonTests(unittest.TestCase):
    def test_positive_numeric_exact_qname_context_unit_and_original_locator(self):
        idx=indexed();kind,reason,ids=compare_fact('youseiushida','line_items',numeric(),idx)
        self.assertEqual((kind,reason),('exact_match',None));self.assertEqual(len(ids),1)
        f=next(x for x in idx['facts'] if x['origin_id']==ids[0]);self.assertEqual(f['source_class'],'official_original')
        self.assertTrue(f['member_sha256']);self.assertTrue(f['unit']['numerator']);self.assertTrue(f['element_index'])

    def test_similar_tag_is_not_mapping(self):
        self.assertEqual(compare_fact('youseiushida','line_items',numeric(concept='{urn:other}NetSales'),indexed())[0],'extraction_difference')

    def test_different_context_remains_separate(self):
        self.assertEqual(compare_fact('youseiushida','line_items',numeric(context_id='Other'),indexed())[0],'context_difference')

    def test_queria_requires_an_unambiguous_original_context_too(self):
        idx=indexed()
        for fact in idx['facts']:fact['context']=None
        row={'element_id':'p:NetSales','context_id':'CurrentYearDuration','unit_id':'yen','value':'123000000'}
        self.assertEqual(compare_fact('queria','stg_financial_facts',row,idx)[1],'original_context_ambiguous')

    def test_unit_difference_is_not_rescaled(self):
        self.assertEqual(compare_fact('youseiushida','line_items',numeric(unit_ref='shares'),indexed())[0],'unit_difference')

    def test_scope_and_period_differences(self):
        for change,expected in [({'period_end':'2020-01-01'},'context_difference'),
            ({'dimensions_json':'[{"axis":"ConsolidatedOrNonConsolidatedAxis","member":"standalone"}]'},'scope_difference')]:
            self.assertEqual(compare_fact('youseiushida','line_items',numeric(**change),indexed())[0],expected)

    def test_duplicate_original_members_are_not_arbitrarily_selected(self):
        kind,reason,ids=compare_fact('youseiushida','line_items',numeric(),indexed(extra=instance()))
        self.assertEqual((kind,reason),('unresolved','original_element_ambiguous'));self.assertEqual(len(ids),2)

    def test_quaria_raw_numeric_and_numad_text_share_origin_without_merging(self):
        idx=indexed();r={'element_id':'p:NetSales','context_id':'CurrentYearDuration','unit_id':'yen','value':'123000000'}
        self.assertEqual(compare_fact('queria','stg_financial_facts',r,idx)[0],'exact_match')
        xml=instance('<c:BusinessTextBlock contextRef="CurrentYearDuration">&lt;p&gt;synthetic text&lt;/p&gt;</c:BusinessTextBlock>')
        idx=indexed(xml);r={'tag':'BusinessTextBlock','text':'synthetic text'}
        self.assertEqual(compare_fact('numad','text_blocks',r,idx)[0],'exact_match')
        r['text']='different';self.assertEqual(compare_fact('numad','text_blocks',r,idx)[0],'text_difference')

    def test_company_specific_element_can_tie_but_not_become_canonical(self):
        idx=indexed(instance('<custom:Unmapped contextRef="CurrentYearDuration" unitRef="yen">7</custom:Unmapped>'))
        self.assertEqual(compare_fact('youseiushida','line_items',numeric(concept='{urn:synthetic:company}Unmapped',value_numeric='7'),idx)[0],'exact_match')

    def test_nil_state_is_not_silently_filled(self):
        self.assertEqual(compare_fact('youseiushida','line_items',numeric(is_nil=True),indexed())[1],'nil_state_differs')

    def test_corrupt_zip_and_xml_declaration_rejected(self):
        for raw in (b'bad',archive(instance().replace(b'<x:xbrl',b'<!DOCTYPE x [<!ENTITY x "y">]><x:xbrl'))):
            with self.assertRaises(ContractError):original_index(raw,{'doc_id':'S0000001','byte_sha256':sha256(raw),'byte_count':len(raw)},document())

    def test_original_byte_hash_failure(self):
        raw,a,d,_,_=extract();a['byte_sha256']='0'*64
        with self.assertRaisesRegex(ContractError,'integrity'):original_index(raw,a,d)

    def test_context_has_period_dimensions_and_member_locator(self):
        idx=indexed();c=idx['contexts'][0]
        row={'context_id':c['context_id'],'period_start':'2021-04-01','dimensions_json':None}
        self.assertEqual(compare_context(row,idx)[0],'exact_match');row['period_start']='1900-01-01'
        self.assertEqual(compare_context(row,idx)[0],'context_difference')

    def test_flattened_definition_relation_does_not_promote_mapping(self):
        self.assertEqual(compare_relation('def_parents',{'child_concept':'Unmapped','parent_standard_concept':'NetSales'},indexed())[0],'unresolved')

    def test_calculation_relation_matches_actual_arc(self):
        idx={'relations':[{'origin_id':'synthetic-arc','arcrole':'http://www.xbrl.org/2003/arcrole/summation-item',
            'role_uri':'synthetic-role','parent_href':'a#p_A','child_href':'a#p_B','weight':'1','order':'2'}]}
        r={'role_uri':'synthetic-role','parent_href':'a#p_A','child_href':'a#p_B','weight':1.0,'order':2.0}
        self.assertEqual(compare_relation('calc_edges',r,idx)[0],'exact_match');r['weight']=-1
        self.assertEqual(compare_relation('calc_edges',r,idx)[0],'extraction_difference')

    def test_provider_normalized_view_selects_explicit_components_only(self):
        rows=[{'provider_fields':{'doc_id':'S0000001','element_id':'jpcrp_cor:NetSalesSummaryOfBusinessResults',
            'context_id':'CurrentYearDuration'+suffix,'value':value}} for suffix,value in [('', '1'),('_NonConsolidatedMember','2')]]
        self.assertEqual(mart_components({'doc_id':'S0000001','year_offset':0},'net_sales',rows),rows[:1])
        self.assertEqual(mart_components({'doc_id':'S0000001','year_offset':-1},'net_sales',rows),[])

    def test_nonfinite_values_are_not_matches(self):
        self.assertFalse(scalar_equal('NaN','NaN'));self.assertFalse(scalar_equal('Infinity','Infinity'))


class PrivateP5Tests(unittest.TestCase):
    def setUp(self):
        p3_fixture.P3AuditTests.setUp(self);p3_fixture.P3AuditTests.audit(self)
        self.p3=self.base/'output/synthetic-p3';self.input=self.base/'derived-input';self.input.mkdir();self.store=PrivateStore(self.input)
        self.doc=json.loads((self.p3/'documents.jsonl').read_bytes().splitlines()[0]);self.did=self.doc['doc_id']
        m=self.doc['metadata_locators'][0]['provider_fields']
        self.meta={'doc_id':self.did,'edinet_code':self.doc['edinet_code'],'sec_code':self.doc.get('secCode'),
            'period_start':m['periodStart'],'period_end':m['periodEnd'],'submit_date':self.doc['submit_datetime'][:10]}
        self.bundle={'selection':{'doc_ids':[self.did],'p3_document_sha256':sha256((self.p3/'documents.jsonl').read_bytes())},
            'assets':[],'rows':[],'sources':{x:{'source_id':x,'provider_version':'synthetic','documentation':[]} for x in ('queria','youseiushida','numad')}}
        self.add('queria','mart_documents',[self.meta]);self.add('youseiushida','filings',[self.meta])
        self.add('queria','mart_companies',[{'edinet_code':self.doc['edinet_code'],'sec_code':None,'filer_name':'DIFFERENT NAME'}])
        self.add('queria','stg_financial_facts',[{'doc_id':self.did,'element_id':'p:NetSales','context_id':'CurrentYearDuration','unit_id':'yen','value':'123000000'}])
        self.add('youseiushida','line_items',[numeric(doc_id=self.did)])
        self.add('numad','text_blocks',[dict(self.meta,tag='AccountingStandardsDEI',text='Japan GAAP',company_name='IGNORED')])
        self.write()

    def add(self,source,table,fields):
        raw=b''.join(encoded(r)+b'\n' for r in fields);a={'byte_sha256':sha256(raw),'byte_count':len(raw),'retrieved_at':'2026-01-01T00:00:00Z'}
        self.store.publish('raw/'+a['byte_sha256'],raw)
        asset={'source_id':source,'table':table,'format':'synthetic_jsonl','doc_scope':[self.did],
               'evidence':{'artifacts':[a]},'schema':sorted(fields[0])};asset['asset_id']=sha256(encoded(asset));self.bundle['assets'].append(asset)
        for i,p in enumerate(fields,1):
            r={'source_id':source,'table':table,'provider_fields':p,'asset_id':asset['asset_id'],
               'locator':{'line_number':i,'row_sha256':sha256(encoded(p))},'extraction_method':'synthetic_fixture'}
            r['source_row_id']=sha256(encoded(r));self.bundle['rows'].append(r)

    def write(self): (self.input/'bundle.json').write_bytes(encoded(self.bundle))
    def audit(self):
        with redirect_stdout(io.StringIO()):return run(self.root,self.p3,self.input,self.base/'p5','synthetic-p5',synthetic=True)

    def test_end_to_end_private_outputs_mirror_group_and_canonical_preservation(self):
        before={p:snapshot_fingerprints(p) for p in (self.root,self.p3,self.input)};result=self.audit()
        self.assertEqual(result['verified_source_rows'],6);self.assertGreater(result['comparison_counts']['exact_match'],0)
        self.assertEqual(result['unique_official_evidence_groups'],1);self.assertEqual(result['mirror_independent_evidence_increment'],0)
        self.assertEqual(before,{p:snapshot_fingerprints(p) for p in before})
        out=self.base/'p5/synthetic-p5'
        for f in ('audit_plan.json','source_acceptance.json','source_artifacts.json','derived_observations.jsonl','official_observations.jsonl',
                  'document_links.jsonl','source_matrix.jsonl','comparison_ledger.jsonl','lineage.jsonl','failure_ledger.jsonl','coverage_summary.json','preservation_proof.json'):
            self.assertTrue((out/f).exists())
        records=[json.loads(x) for x in (out/'comparison_ledger.jsonl').read_bytes().splitlines()]
        self.assertTrue(all(r['synthetic'] and not r['export_allowed'] and not r['canonical_mapping_promoted'] for r in records))
        self.assertTrue(any(r['canonical_fact_ids'] for r in records));self.assertTrue(all(r['provider_available_at'] is None for r in records))

    def test_doc_id_entity_sec_code_period_and_date_mismatch_no_name_fallback(self):
        for key,bad in [('doc_id','S0000009'),('edinet_code','E99999'),('sec_code','123A0'),('period_end','1999-01-01'),('submit_date','1999-01-01')]:
            self.assertIsNotNone(document_link(dict(self.meta,**{key:bad}),self.doc))
        self.assertIsNone(document_link(dict(self.meta,company_name='ARBITRARY'),self.doc))

    def test_revision_difference_not_parent_fallback(self):
        self.assertEqual(document_link(dict(self.meta,parent_doc_id='S9999999'),self.doc),'revision_difference')

    def test_duplicate_document_metadata_blocks_source(self):
        self.add('queria','mart_documents',[self.meta]);self.write();result=self.audit()
        self.assertIn('source_document_ambiguous',result['failure_reasons'])

    def test_missing_table_gets_grid_and_failure_reason(self):
        result=self.audit();self.assertIn('source_table_not_acquired',result['failure_reasons'])

    def test_byte_corruption_blocks_instead_of_admitting_rows(self):
        path=self.input/'raw'/self.bundle['assets'][0]['evidence']['artifacts'][0]['byte_sha256'];path.write_bytes(b'broken')
        verified,failures=verify_source_rows(self.store,self.bundle,True)
        self.assertEqual(len(verified),4) # the two metadata sources share identical synthetic bytes
        self.assertTrue(all(f['status']=='BLOCKED' for f in failures))

    def test_changed_source_value_or_locator_cannot_reverse_verify(self):
        b=deepcopy(self.bundle);b['rows'][0]['provider_fields']['edinet_code']='E99999'
        _,f=verify_source_rows(self.store,b,True);self.assertTrue(f)
        b=deepcopy(self.bundle);b['rows'][0]['locator']['line_number']=999
        _,f=verify_source_rows(self.store,b,True);self.assertTrue(f)

    def test_synthetic_bytes_cannot_be_reported_empirical(self):
        _,failures=verify_source_rows(self.store,self.bundle,False)
        self.assertEqual(len(failures),len(self.bundle['assets']))
        with self.assertRaisesRegex(ContractError,'synthetic_not_empirical'):
            run(self.root,self.p3,self.input,self.base/'p5-real','test')

    def test_public_checkout_output_and_input_rejected(self):
        git=self.base/'git';git.mkdir();(git/'.git').mkdir()
        with self.assertRaises(ContractError):run(self.root,self.p3,self.input,git,'test',synthetic=True)
        with self.assertRaises(ContractError):run(self.root,self.p3,self.input,self.input,'test',synthetic=True)

    def test_existing_snapshot_cannot_be_overwritten(self):
        self.audit()
        with self.assertRaisesRegex(ContractError,'snapshot_already_exists'):self.audit()


class RangeEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.store=PrivateStore(Path(tmp.name)/'private');self.calls=[]
    def opener(self,request,timeout):
        self.calls.append(request);start,end=map(int,request.headers['Range'][6:].split('-'))
        r=io.BytesIO(b'abcdefghij'[start:end+1]);r.status=206;r.headers={'Content-Range':f'bytes {start}-{end}/10','ETag':'"synthetic"'};return r
    def test_reexecution_reuses_identical_bytes_manifest_and_checkpoint(self):
        args=(self.store,'https://example.org/synthetic','synthetic')
        a=fetch(*args,start=0,size=3,opener=self.opener);before=snapshot_fingerprints(self.store.root)
        self.assertEqual(a,fetch(*args,start=0,size=3,opener=self.opener));self.assertEqual(len(self.calls),1)
        self.assertEqual(before,snapshot_fingerprints(self.store.root))
    def test_wrong_content_range_rejected(self):
        def wrong(req,timeout):
            r=self.opener(req,timeout);r.headers['Content-Range']='bytes 0-2/10';return r
        with self.assertRaisesRegex(ContractError,'range_not_honored'):fetch(self.store,'https://example.org/synthetic','v1',start=3,size=3,opener=wrong)
    def test_range_reader_and_offline_replay_keep_partial_scope(self):
        f=RangeFile(self.store,'https://example.org/synthetic','v1',2,6,opener=self.opener);self.assertEqual(f.read(3),b'cde');self.assertEqual(f.read(),b'fgh')
        e={'member_size':6,'member_offset':2,'artifacts':f.artifacts};replay=RecordedRanges(self.store,e)
        self.assertEqual(replay.read(),b'cdefgh');self.assertTrue(all(a['artifact_scope']=='range_bytes' for a in f.artifacts))
    def test_range_hole_does_not_fetch_network(self):
        f=RangeFile(self.store,'https://example.org/synthetic','v1',0,10,opener=self.opener);f.read(2)
        with self.assertRaisesRegex(ContractError,'recorded_range_missing'):RecordedRanges(self.store,{'member_size':10,'artifacts':f.artifacts}).read()
    def test_changed_etag_rejected(self):
        def changed(req,timeout):
            r=self.opener(req,timeout);r.headers['ETag']=str(len(self.calls));return r
        f=RangeFile(self.store,'https://example.org/synthetic','v1',0,10,opener=changed);f.read(2)
        with self.assertRaisesRegex(ContractError,'range_version_changed'):f.read(2)
    def test_raw_corruption_on_checkpoint_rejected(self):
        _,a=fetch(self.store,'https://example.org/synthetic','v1',start=0,size=2,opener=self.opener)
        (self.store.root/'raw'/a['byte_sha256']).write_bytes(b'xx')
        with self.assertRaises(ContractError):fetch(self.store,'https://example.org/synthetic','v1',start=0,size=2,opener=self.opener)
    def test_credential_query_and_budget_rejected(self):
        with self.assertRaises(ContractError):fetch(self.store,'https://example.org/a?token=synthetic','v1',opener=self.opener)
        f=RangeFile(self.store,'https://example.org/synthetic','v1',0,10,budget=2,opener=self.opener)
        with self.assertRaisesRegex(ContractError,'budget'):f.read(3)


if __name__=='__main__':unittest.main()
