"""Source cache identities do not depend on partition selection or inferred dates."""
import unittest
from expansion_sources import source_observation,derived_row
from source_acquisition import encoded,sha256


class SourceIdentityTests(unittest.TestCase):
    def test_cached_source_id_matches_original_csv_record_rule(self):
        a={'byte_sha256':'a'*64};row={'Code':'123A0','Date':'2022-01-01','C':'100'}
        result=source_observation(a,17,row,'equities_bars_daily',True)
        self.assertEqual(result['observation_id'],sha256(encoded(['a'*64,17,sha256(encoded(row))])))
        self.assertNotIn('public_available_at',result)
        self.assertEqual(result['provider_fields']['Code'],'123A0')

    def test_changed_record_value_or_locator_changes_id(self):
        a={'byte_sha256':'b'*64};r={'Code':'12345','Date':'2022-01-01'}
        one=source_observation(a,1,r,'equities_master')
        self.assertNotEqual(one['observation_id'],source_observation(a,2,r,'equities_master')['observation_id'])
        self.assertNotEqual(one['observation_id'],source_observation(a,1,dict(r,Code='12346'),'equities_master')['observation_id'])

    def test_derived_row_reuses_provider_asset_identity(self):
        a={'asset_id':'c'*64,'source_id':'numad','table':'text_blocks'}
        r=derived_row(a,{'doc_id':'S0000001','tag':'SyntheticTextBlock','text':'SYNTHETIC'},{'line_number':1})
        self.assertEqual(r['asset_id'],a['asset_id']);self.assertEqual(r['extraction_method'],'pinned_jsonl')
        self.assertEqual(r['source_row_id'],sha256(encoded({k:v for k,v in r.items() if k!='source_row_id'})))
        self.assertNotIn('independent_evidence',r)

    def test_queria_source_projection_keeps_original_extraction_identity(self):
        a={'asset_id':'d'*64,'source_id':'queria','table':'stg_financial_facts'}
        r=derived_row(a,{'doc_id':'S0000001','value':'7'},{'row_group':0,'row_index':1})
        self.assertEqual(r['extraction_method'],'provider_stg_source_projection')


if __name__=='__main__':unittest.main()
