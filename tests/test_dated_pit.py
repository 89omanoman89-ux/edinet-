"""Synthetic only: direct observations, schedule reconstruction and ex-post isolation."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import unittest

from dated_pit import (dated_mapping, reconstruct_price, prepare_join, join_dated_fact,
                       execution_outcome, verify_dated_lineage, edinet_identity_evidence)
from evidence_core import ContractError
from financial_facts import reverse_verify, definitions
from jquants_local import JQuantsArchive, DATASETS
from metadata_gap_audit import snapshot_fingerprints, ReadOnlyEvidence
from p4_audit import run
from source_acquisition import PrivateStore, encoded, sha256
import test_pit_market as market
import test_p3_audit as p3_fixture
from test_jquants_local import write_source


class DatedPITTests(unittest.TestCase):
    def setUp(self):
        self.legacy=market.PITMarketTests();self.legacy.setUp()
        self.fact=self.legacy.fact;self.decision=self.legacy.decision
        fields={'docID':self.fact['doc_id'],'edinetCode':self.fact['edinet_code'],'secCode':'123A0','seqNumber':1}
        self.anchor={'doc_id':self.fact['doc_id'],'edinet_code':self.fact['edinet_code'],'secCode':'123A0','doc_type':'120',
            'public_available_at':self.fact['public_available_at'],'synthetic':True,'status':'PASS','missing_reason':None,
            'sources':[{'provider_fields':fields,'row_sha256':sha256(encoded(fields))}],'identity_evidence_id':'synthetic-anchor'}
        self.masters=[market.observation({'Date':d,'Code':'123A0','ProdCat':'011','Mkt':'0111','MktNm':'synthetic','CoName':'not used'},'equities_master')
                      for d in ('2022-05-31','2022-06-01','2022-06-02')]
        original=self.legacy.price
        channels={original['source']['artifact']['relative_path']:{'status':'PASS','channel':'bulk_csv','endpoint':'/equities/bars/daily',
                    'file_sha256':original['source']['artifact']['byte_sha256']}}
        self.price=reconstruct_price(original,channels);self.calendar=self.legacy.calendar
        self.ids={r['observation_id'] for r in [self.price,*self.masters,*self.calendar]}

    def prepare(self,**overrides):
        params=dict(decision_at=self.decision,other_anchors=[self.anchor]);params.update(overrides)
        return prepare_join(self.anchor,self.masters,[self.price],self.calendar,self.ids,**params)

    def join(self,plan=None,view=None):
        return join_dated_fact(self.fact,view or self.legacy.view(),plan or self.prepare(),decision_at=self.decision,
                              verified_fact_ids={self.fact['fact_id']},allow_synthetic_for_tests=True)

    def test_positive_join_has_exact_dated_sources_without_lifetime_intervals(self):
        p=self.prepare();r=self.join(p);self.assertEqual(r['status'],'PASS')
        self.assertIsNone(r['identifier_validity']);self.assertIsNone(r['listing_period'])
        self.assertEqual(p['mapping']['listing_basis'],'direct_dated_listing_observation')
        self.assertEqual(reverse_verify(self.legacy.data,self.legacy.artifact,self.legacy.doc,definitions(),[self.fact])['status'],'PASS')
        views=[{'trigger_doc_id':r['doc_id'],'decision_at':self.decision,'selected_fact_ids':[self.fact['fact_id']]}]
        self.assertEqual(verify_dated_lineage([r],[self.fact],[self.anchor],[p['mapping']],
            [self.price,*self.masters,*self.calendar],{self.fact['fact_id']},views)['checked_positive_rows'],1)

    def test_four_five_and_alpha_codes_require_exact_observation(self):
        for code in ('1234','12340','123A','123A0'):
            a=dict(self.anchor,secCode=code)
            rows=[market.observation(dict(m['provider_fields'],Code=code),'equities_master') for m in self.masters]
            m=dated_mapping(a,rows,['2022-06-01'],{r['observation_id'] for r in rows},decision_at=self.decision)
            self.assertEqual(m['status'],'PASS');self.assertEqual(m['jquants_code'],code)
        a=dict(self.anchor,secCode='123A')
        self.assertEqual(dated_mapping(a,self.masters,['2022-06-01'],self.ids,decision_at=self.decision)['status'],'BLOCKED')

    def test_names_never_participate_in_mapping(self):
        for n,m in enumerate(self.masters):m['provider_fields']['CoName']='different synthetic name '+str(n)
        self.assertEqual(self.prepare()['status'],'PASS')

    def test_duplicate_master_rows_not_arbitrarily_selected(self):
        self.masters.append(deepcopy(self.masters[1]))
        self.assertEqual(self.prepare()['missing_reason'],'dated_master_ambiguous')

    def test_price_decision_entry_each_require_own_listing_observation(self):
        for i in range(3):
            saved=self.masters;self.masters=saved[:i]+saved[i+1:]
            self.assertEqual(self.prepare()['missing_reason'],'dated_master_missing_or_code_mismatch')
            self.masters=saved

    def test_code_change_is_not_joined_across_dates(self):
        self.masters[-1]['provider_fields']['Code']='99990'
        self.assertEqual(self.prepare()['status'],'BLOCKED')

    def test_known_code_reuse_blocks_but_future_identity_does_not_leak_back(self):
        other=dict(self.anchor,edinet_code='E00002',identity_evidence_id='other')
        self.assertEqual(self.prepare(other_anchors=[other])['missing_reason'],'code_reuse_or_entity_conflict')
        other['public_available_at']='2023-01-01T00:00:00+09:00'
        self.assertEqual(self.prepare(other_anchors=[other])['status'],'PASS')

    def test_wrong_or_unknown_product_and_market_block(self):
        for field,value,reason in [('ProdCat','014','product_category_incompatible'),('ProdCat','','product_category_incompatible'),
                                   ('Mkt','unknown','market_unknown_or_incompatible')]:
            old=self.masters[1]['provider_fields'][field];self.masters[1]['provider_fields'][field]=value
            self.assertEqual(self.prepare()['missing_reason'],reason);self.masters[1]['provider_fields'][field]=old

    def test_unknown_channel_cannot_borrow_official_schedule(self):
        r=reconstruct_price(self.legacy.price,{})
        self.assertIsNone(r['public_available_at']);self.assertEqual(r['time_evidence']['level'],'unknown')

    def test_official_schedule_is_labeled_and_not_historical_acquisition(self):
        self.assertEqual(self.price['public_available_at'],'2022-06-01T00:00:00+09:00')
        e=self.price['time_evidence'];self.assertEqual(e['level'],'official_provider_schedule_reconstruction')
        self.assertFalse(e['historical_delivery_observed']);self.assertFalse(e['rule']['is_delivery_guarantee'])
        self.assertTrue(all(s['url'].startswith('https://jpx-jquants.com/') for s in e['specs'].values()))

    def test_future_price_is_rejected_and_missing_prior_day_not_backfilled(self):
        self.price['public_available_at']=self.decision
        self.assertEqual(self.prepare()['missing_reason'],'price_not_yet_available')
        self.price['date']='2022-05-30'
        self.assertEqual(self.prepare()['missing_reason'],'price_missing')

    def test_future_entry_master_is_separate_from_decision_information(self):
        r=self.join();future=self.masters[-1]['observation_id']
        self.assertIn(future,r['entry_validation_master_ids']);self.assertNotIn(future,r['decision_information']['master_observation_ids'])
        self.assertEqual(r['trading_session']['evidence_level'],'current_reconstruction')
        self.assertIsNone(r['trading_session']['public_available_at']);self.assertFalse(r['execution_claim'])

    def test_missing_calendar_still_blocks(self):
        self.calendar=[r for r in self.calendar if r['provider_fields']['Date']!='2022-06-02']
        self.assertEqual(self.prepare()['missing_reason'],'trading_calendar_missing_or_ambiguous')

    def test_p3_null_and_revision_block_are_not_filled(self):
        self.fact['normalized_value']=None;self.fact['missing_reason']='reported_nil'
        self.assertEqual(self.join()['missing_reason'],'reported_nil')
        self.fact['normalized_value']='123000000'
        view={'mode':'as_of','decision_at':self.decision,'facts':[],
              'blocked':[{'doc_ids':[self.fact['doc_id']],'reason':'revision_raw_missing'}]}
        self.assertEqual(self.join(view=view)['missing_reason'],'revision_raw_missing')

    def test_source_tampering_is_caught_by_reverse_lineage(self):
        p=self.prepare();r=self.join(p);r['price']='999'
        with self.assertRaisesRegex(ContractError,'market_row_lineage_mismatch'):
            verify_dated_lineage([r],[self.fact],[self.anchor],[p['mapping']],[self.price,*self.masters,*self.calendar],
                {self.fact['fact_id']},[{'trigger_doc_id':r['doc_id'],'decision_at':self.decision,'selected_fact_ids':[self.fact['fact_id']]}])

    def test_execution_outcome_four_states_and_no_roll_forward(self):
        session=self.prepare()['session'];baseline=self.join()
        traded=market.observation({'Date':'2022-06-02','Code':'123A0','O':'80','H':'82','L':'79','C':'81','Vo':'100','Va':'8100'})
        empty=market.observation(dict(traded['provider_fields'],**{k:'' for k in ('O','H','L','C','Vo','Va')}))
        partial=market.observation(dict(traded['provider_fields'],Vo=''))
        tomorrow=market.observation(dict(traded['provider_fields'],Date='2022-06-03'))
        for rows,expected in [([traded],'traded'),([empty,tomorrow],'no_observed_trade'),([tomorrow],'price_unavailable'),
                              ([partial],'ambiguous'),([traded,traded],'ambiguous')]:
            out=execution_outcome('123A0',session,rows,{r['observation_id'] for r in rows})
            self.assertEqual(out['status'],expected);self.assertEqual(out['entry_at'],session['start'])
            self.assertFalse(out['decision_feature']);self.assertFalse(out['execution_claim'])
            self.assertEqual(self.join(),baseline)


class DatedPrivateAuditTests(unittest.TestCase):
    def setUp(self):
        p3_fixture.P3AuditTests.setUp(self)
        listing=self.root/'listings/2022-06-01/documents.json';payload=json.loads(listing.read_bytes())
        for r in payload['results']:r['secCode']='123A0'
        listing.write_bytes(encoded(payload))
        frame=[json.loads(x) for x in (self.p2/'universe_documents.jsonl').read_bytes().splitlines()]
        for f in frame:
            for e in f['metadata_events']:
                e['provider_fields']['secCode']='123A0';e['listing']['byte_sha256']=sha256(listing.read_bytes())
        (self.p2/'universe_documents.jsonl').write_bytes(b''.join(encoded(x)+b'\n' for x in frame))
        p3_fixture.P3AuditTests.audit(self)
        self.p3=self.base/'output/synthetic-p3';self.jq=self.base/'jq';self.jq.mkdir()
        for dataset in DATASETS:
            if dataset=='markets_calendar': rows=[r['provider_fields'] for r in market.calendar()]
            elif dataset=='equities_master': rows=[{'Date':d,'Code':'123A0','Mkt':'0111','MktNm':'synthetic','ProdCat':'011'} for d in ('2022-05-31','2022-06-01','2022-06-02')]
            elif dataset=='equities_bars_daily': rows=[{'Date':d,'Code':'123A0','O':'80','H':'82','L':'79','C':'81','Vo':'100','Va':'8100','AdjFactor':'1'} for d in ('2022-05-31','2022-06-02')]
            else: rows=[{'DiscDate':'2022-05-31','DiscTime':'15:00:00','Code':'123A0','DiscNo':'synthetic','DocType':'FYFinancialStatements_Consolidated_JP','CurPerType':'FY','CurPerSt':'2021-04-01','CurPerEn':'2022-03-31','Sales':'1'}]
            p=write_source(self.jq,dataset,rows);m=json.loads((p.parent/'manifest.json').read_bytes())
            key=dataset+'/synthetic.csv.gz';bulk=encoded({'data':[{'Key':key,'Size':p.stat().st_size}]})
            (p.parent/'bulk_list.json').write_bytes(bulk)
            m.update(mode='bulk',endpoint='/'+dataset.replace('_','/'),bulk_list_sha256=sha256(bulk));m['files'][0]['source_key']=key
            (p.parent/'manifest.json').write_bytes(encoded(m))

    def audit(self):
        with redirect_stdout(io.StringIO()):return run(self.jq,self.root,self.p3,self.base/'dated','synthetic-dated',synthetic=True,direct_dated=True)

    def test_positive_private_roundtrip_preserves_inputs(self):
        before={p:snapshot_fingerprints(p) for p in (self.root,self.p2,self.p3,self.jq)}
        result=self.audit();self.assertEqual(result['complete_pit_joins'],2)
        self.assertEqual(result['positive_join_documents'],2)
        self.assertEqual(before,{p:snapshot_fingerprints(p) for p in before})
        proof=json.loads((self.base/'dated/synthetic-dated/reverse_verification.json').read_bytes())
        self.assertEqual(proof['dated_lineage']['checked_positive_rows'],2)

    def test_raw_edinet_metadata_mismatch_blocks(self):
        p=self.root/'listings/2022-06-01/documents.json';p.write_bytes(p.read_bytes()+b' ')
        result=self.audit();self.assertEqual(result['complete_pit_joins'],0)
        self.assertIn('edinet_metadata_integrity_failed',result['failure_counts'])

    def test_saved_bulk_list_hash_is_required_for_channel(self):
        p=next((self.jq/'equities_bars_daily').glob('revision=*/bulk_list.json'));p.write_bytes(p.read_bytes()+b' ')
        result=self.audit();self.assertEqual(result['complete_pit_joins'],0)
        self.assertIn('acquisition_channel_unknown',result['failure_counts'])

    def test_unknown_channel_stays_blocked(self):
        p=next((self.jq/'equities_bars_daily').glob('revision=*/manifest.json'));m=json.loads(p.read_bytes());m['mode']='unknown';p.write_bytes(encoded(m))
        result=self.audit();self.assertEqual(result['complete_pit_joins'],0)


if __name__=='__main__': unittest.main()
