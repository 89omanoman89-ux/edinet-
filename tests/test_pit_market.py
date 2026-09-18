"""All identities, source rows, values and trading assertions are synthetic."""
from copy import deepcopy
from datetime import date, datetime, timedelta
import unittest

from evidence_core import ContractError
from financial_facts import definitions, reverse_verify
from financial_views import fact_view
from jquants_local import code
from pit_market import (entry_candidate, resolve_security, choose_price, join_fact, reconcile_sources,
                        financial_observations, price_observation)
from source_acquisition import encoded, sha256
import test_financial_facts as fixture


def observation(fields, dataset="equities_bars_daily"):
    digest = sha256(encoded(fields))
    return {"observation_id": digest, "dataset": dataset, "provider_fields": fields,
        "source": {"artifact": {"byte_sha256": digest, "relative_path": "synthetic.csv", "byte_count": len(encoded(fields))},
                   "record_index": 1, "row_sha256": digest}, "synthetic": True}


def calendar(start="2022-05-30", count=15):
    day = date.fromisoformat(start)
    return [observation({"Date": (day+timedelta(days=i)).isoformat(), "HolDiv": "0" if (day+timedelta(days=i)).weekday() >= 5 else "1"},
                        "markets_calendar") for i in range(count)]


class PITMarketTests(unittest.TestCase):
    def setUp(self):
        self.data, self.artifact, self.doc, _, fs = fixture.extract()
        self.fact = fs[0]; self.decision = "2022-06-01T15:01:00.000001+09:00"
        self.cutoff = datetime.fromisoformat("2026-09-19T00:00:00+00:00")
        self.calendar = calendar()
        self.mapping = {"mapping_id": "synthetic-mapping", "entity_id": "edinet:E00001", "issuer_entity_id": "edinet:E00001",
            "security_id": "synthetic-ordinary-share", "jquants_code": "123A0", "status": "PASS",
            "identifier_validity_from": "2020-01-01", "identifier_validity_to": "2023-01-01", "identifier_validity_verified": True,
            "listing_from": "2020-01-01", "listing_to": "2023-01-01", "listing_verified": True,
            "public_available_at": "2020-01-01T00:00:00+09:00", "matching_method": "explicit_dated_identifier_evidence",
            "mapping_evidence": [observation({"synthetic_assertion": "dated_identity"})["source"]], "synthetic": True}
        self.price = dict(price_observation(observation({"Code": "123A0", "Date": "2022-05-31", "C": "80", "O": "79", "AdjFactor": "1"})),
            public_available_at="2022-05-31T17:00:00+09:00", missing_reason=None)
        self.status = {"security_id": "synthetic-ordinary-share", "valid_from": "2022-06-01T00:00:00+09:00",
            "valid_to": "2022-06-10T00:00:00+09:00", "public_available_at": "2022-05-31T17:00:00+09:00",
            "status": "tradable", "source": observation({"synthetic_assertion": "trading_status"})["source"], "synthetic": True}

    def view(self, docs=None, facts=None):
        return fact_view(facts or [self.fact], docs or [self.doc], mode="as_of", decision_at=datetime.fromisoformat(self.decision),
                         snapshot_cutoff=self.cutoff, allow_synthetic_for_tests=True)

    def join(self, **changes):
        args = dict(decision_at=self.decision, verified_fact_ids={self.fact["fact_id"]},
                    verified_observation_ids={r['observation_id'] for r in [self.price, *self.calendar]}, allow_synthetic_for_tests=True)
        args.update(changes)
        return join_fact(self.fact, self.view(), [self.mapping], self.calendar, [self.price], [self.status], **args)

    def test_complete_join_points_to_both_sources_and_original_xbrl(self):
        r = self.join(); self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["entry_at"], "2022-06-02T09:00:00+09:00")
        self.assertEqual(r["jquants_source"], self.price["source"])
        self.assertEqual(r["mapping_evidence"], self.mapping["mapping_evidence"])
        self.assertEqual(r["edinet_source"]["source_artifact_sha256"], self.artifact["byte_sha256"])
        self.assertEqual(reverse_verify(self.data, self.artifact, self.doc, definitions(), [self.fact])["status"], "PASS")
        self.assertEqual(r["research_row_id"], sha256(encoded({k:v for k,v in r.items() if k != "research_row_id"})))
        self.assertFalse(r["execution_claim"]); self.assertFalse(r["export_allowed"])

    def test_codes_remain_strings_without_padding_or_truncation(self):
        for value in ("1234", "12340", "123A", "123A0", "00100"):
            self.assertEqual(code(value), value)
        for value in (12340, "123", "123A00", " 1234", "123a"):
            with self.assertRaises(ContractError): code(value)

    def test_code_change_has_separate_validity_intervals(self):
        old = dict(self.mapping, jquants_code="12340", identifier_validity_to="2022-06-01")
        self.mapping["identifier_validity_from"] = "2022-06-01"
        result = resolve_security([old, self.mapping], "edinet:E00001", self.decision, "2022-06-02T09:00:00+09:00")
        self.assertEqual(result["jquants_code"], "123A0")
        with self.assertRaisesRegex(ContractError, "code_not_valid"):
            resolve_security([old], "edinet:E00001", self.decision, "2022-06-02T09:00:00+09:00")

    def test_multiple_securities_without_explicit_selection_are_ambiguous(self):
        other = dict(self.mapping, security_id="synthetic-preferred-share", jquants_code="123A1")
        with self.assertRaisesRegex(ContractError, "ambiguous_security_mapping"):
            resolve_security([self.mapping, other], "edinet:E00001", self.decision, "2022-06-02T09:00:00+09:00")
        self.assertEqual(resolve_security([self.mapping,other], "edinet:E00001", self.decision, "2022-06-02T09:00:00+09:00", "123A1")["security_id"], other["security_id"])

    def test_same_code_multiple_mapping_candidates_are_blocked(self):
        with self.assertRaisesRegex(ContractError, "ambiguous_security_mapping"):
            resolve_security([self.mapping, dict(self.mapping,security_id="other")], "edinet:E00001", self.decision, "2022-06-02T09:00:00+09:00", "123A0")

    def test_unknown_identity_and_future_mapping_evidence_block(self):
        self.mapping["identifier_validity_verified"] = False
        self.assertEqual(self.join()["missing_reason"], "identifier_validity_not_established")
        self.mapping["identifier_validity_verified"] = True; self.mapping["public_available_at"] = self.decision
        self.assertEqual(self.join()["missing_reason"], "mapping_not_yet_available")

    def test_listing_and_delisting_are_not_code_validity(self):
        for field, value in (("listing_from", "2022-06-03"), ("listing_to", "2022-06-02")):
            with self.subTest(field=field):
                old = self.mapping[field]; self.mapping[field] = value
                self.assertEqual(self.join()["missing_reason"], "not_listed_at_decision_or_entry")
                self.mapping[field] = old

    def test_split_factor_retained_without_changing_reported_price_or_shares(self):
        self.price = dict(price_observation(observation(dict(self.price['provider_fields'], AdjFactor='0.5'))),
                          public_available_at=self.price['public_available_at'], missing_reason=None)
        r = self.join(); self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["price"], "80"); self.assertEqual(r["adjustment_factor"], "0.5")
        self.assertEqual(r["normalized_value"], self.fact["normalized_value"])

    def test_adjusted_price_unknown_and_future_basis_are_rejected(self):
        self.price["price_basis"] = "provider_adjusted"
        self.assertEqual(self.join()["missing_reason"], "adjusted_price_vintage_unknown")
        self.price["adjustment_basis_at"] = "2023-01-01T00:00:00+09:00"
        self.assertEqual(self.join()["missing_reason"], "future_corporate_action_adjustment")

    def test_holiday_and_ose_holiday_are_not_cash_sessions(self):
        for hol in ("0", "3"):
            rows = calendar(); next(r for r in rows if r["provider_fields"]["Date"] == "2022-06-02")["provider_fields"]["HolDiv"] = hol
            self.assertEqual(entry_candidate(self.fact["public_available_at"], self.decision, rows)["date"], "2022-06-03")

    def test_missing_calendar_day_is_not_guessed_from_weekday(self):
        self.calendar = [r for r in self.calendar if r["provider_fields"]["Date"] != "2022-06-02"]
        self.assertEqual(self.join()["missing_reason"], "trading_calendar_missing_or_ambiguous")

    def test_intraday_and_after_close_disclosure_wait_for_next_daily_session(self):
        for hour in (10, 16):
            public = f"2022-06-01T{hour}:00:00+09:00"; decision = f"2022-06-01T{hour}:00:01+09:00"
            self.assertEqual(entry_candidate(public, decision, self.calendar)["date"], "2022-06-02")

    def test_weekend_disclosure_waits_for_monday(self):
        self.assertEqual(entry_candidate("2022-06-04T15:00:00+09:00", "2022-06-04T15:00:01+09:00", self.calendar)["date"], "2022-06-06")

    def test_suspension_and_unknown_tradability_are_not_price_missing(self):
        self.status["status"] = "suspended"
        self.assertEqual(self.join()["missing_reason"], "trading_suspended")
        r = join_fact(self.fact,self.view(),[self.mapping],self.calendar,[self.price],[],decision_at=self.decision,
                     verified_fact_ids={self.fact["fact_id"]}, verified_observation_ids={r['observation_id'] for r in self.calendar}, allow_synthetic_for_tests=True)
        self.assertEqual(r["missing_reason"], "trading_status_unknown_or_ambiguous")

    def test_price_missing_and_unknown_publication_time_block(self):
        self.price["close"] = None
        self.assertEqual(self.join()["missing_reason"], "price_missing")
        self.price["close"] = "80"; self.price["public_available_at"] = None
        self.assertEqual(self.join()["missing_reason"], "time_precision_unknown")

    def test_same_day_close_and_future_publication_are_not_features(self):
        self.price["date"] = "2022-06-01"
        self.assertEqual(self.join()["missing_reason"], "price_missing")
        self.price["date"] = "2022-05-31"; self.price["public_available_at"] = self.decision
        self.assertEqual(self.join()["missing_reason"], "price_not_yet_available")

    def test_equal_disclosure_decision_is_future_leakage(self):
        with self.assertRaisesRegex(ContractError, "future_information_leakage"):
            entry_candidate(self.fact["public_available_at"], self.fact["public_available_at"], self.calendar)

    def test_source_unverified_and_synthetic_do_not_pass_empirical_gate(self):
        self.assertEqual(self.join(verified_fact_ids=set())["missing_reason"], "edinet_source_lineage_unverified")
        self.assertEqual(self.join(allow_synthetic_for_tests=False)["missing_reason"], "synthetic_not_empirical")

    def test_nil_edinet_value_never_filled_from_market_data(self):
        self.fact["normalized_value"] = None; self.fact["missing_reason"] = "reported_nil"
        r = self.join(); self.assertEqual(r["missing_reason"], "reported_nil"); self.assertIsNone(r["normalized_value"])

    def test_revision_vintage_uses_p3_asof_and_cannot_restore_parent(self):
        d = fixture.document("S0000002", "S0000001", "2022-06-01T15:00:00+09:00")
        d0 = dict(self.doc, public_available_at="2022-05-01T15:00:00+09:00")
        a = fixture.extract(d=d0)[4][0]; b = fixture.extract(d=d)[4][0]
        view = self.view([d0,d],[a,b])
        for f, expected in ((a,"unavailable_edinet_vintage"),(b,None)):
            r = join_fact(f,view,[self.mapping],self.calendar,[self.price],[self.status],decision_at=self.decision,
                          verified_fact_ids={a['fact_id'],b['fact_id']},
                          verified_observation_ids={r['observation_id'] for r in [self.price,*self.calendar]}, allow_synthetic_for_tests=True)
            self.assertEqual(r["missing_reason"],expected)

    def test_revision_branch_and_conflicting_fact_gates_propagate(self):
        view = {"mode":"as_of","decision_at":self.decision,"facts":[],"blocked":[{"doc_ids":[self.doc['doc_id']],"reason":"ambiguous_revision_branches"}]}
        r=join_fact(self.fact,view,[self.mapping],self.calendar,[self.price],[self.status],decision_at=self.decision,
                    verified_fact_ids={self.fact['fact_id']},allow_synthetic_for_tests=True)
        self.assertEqual(r['missing_reason'],'ambiguous_revision_branches'); self.assertIsNone(r['normalized_value'])

    def test_reconciliation_preserves_disagreement_and_time_scope_definition(self):
        other=dict(self.fact,jquants_fact_id='synthetic-jq-fact',normalized_value='7',revision_state='reported_initial_or_unknown')
        r=reconcile_sources(self.fact,other,self.decision,identity_verified=True)
        self.assertIn('value_conflict',r['classifications']);self.assertEqual(self.fact['normalized_value'],'123000000')
        for key,value,reason in [('consolidation','standalone','scope_difference'),('metric','other','definition_difference'),
                                ('accounting_standard','IFRS','accounting_standard_difference'),('restated',True,'revision_difference')]:
            self.assertIn(reason,reconcile_sources(self.fact,dict(other,**{key:value}),self.decision,identity_verified=True)['classifications'])
        self.assertIn('revision_difference',reconcile_sources(self.fact,other,self.decision,identity_verified=True,edinet_is_revision=True)['classifications'])

    def test_equal_values_do_not_merge_source_lineage_or_unverified_identity(self):
        other=dict(self.fact,jquants_fact_id='synthetic-independent',revision_state='reported_initial_or_unknown')
        r=reconcile_sources(self.fact,other,self.decision,identity_verified=True)
        self.assertIn('exact_match',r['classifications']);self.assertNotEqual(r['edinet_fact_id'],r['jquants_fact_id'])
        self.assertIsNone(reconcile_sources(self.fact,other,self.decision,identity_verified=False)['numeric_comparison'])

    def test_future_financial_source_is_not_a_point_in_time_match(self):
        other=dict(self.fact,jquants_fact_id='synthetic-independent',revision_state='reported_initial_or_unknown',public_available_at=self.decision)
        r=reconcile_sources(self.fact,other,self.decision,identity_verified=True)
        self.assertFalse(r['eligible_at_decision']);self.assertNotIn('exact_match',r['classifications'])

    def test_jquants_financial_source_keeps_original_string_and_explicit_semantics(self):
        row=observation({'DocType':'FYFinancialStatements_Consolidated_JP','CurPerType':'FY','Code':'123A0','DiscNo':'synthetic',
            'DiscDate':'2022-05-01','DiscTime':'15:00:00','CurPerSt':'2021-04-01','CurPerEn':'2022-03-31','Sales':'123000000','NP':''},'fins_summary')
        fs=financial_observations(row)
        sales=next(f for f in fs if f['field']=='Sales')
        self.assertEqual(sales['normalized_value'],'123000000'); self.assertEqual(sales['accounting_standard'],'JP GAAP')
        self.assertIsNone(next(f for f in fs if f['field']=='NP')['normalized_value'])
        self.assertEqual(next(f for f in fs if f['field']=='TA')['period_class'],'instant')
        row['provider_fields']['DocType']='EarnForecastRevision'
        self.assertEqual(financial_observations(row),[])

    def test_recycled_code_cannot_take_prior_owner_price(self):
        self.mapping['identifier_validity_from']='2022-06-01'
        self.assertEqual(self.join()['missing_reason'],'price_date_security_identity_unverified')

    def test_market_byte_verification_and_locators_are_required(self):
        self.assertEqual(self.join(verified_observation_ids=set())['missing_reason'],'jquants_source_lineage_unverified')
        self.price['source']['row_sha256']='missing'
        self.assertEqual(self.join()['missing_reason'],'source_locator_invalid')

    def test_price_projection_cannot_disagree_with_verified_source_row(self):
        self.price['close']='999'
        self.assertEqual(self.join()['missing_reason'],'price_projection_source_mismatch')

    def test_synthetic_calendar_cannot_lose_its_classification(self):
        self.fact['synthetic']=False; self.price['synthetic']=False
        self.mapping['synthetic']=False; self.status['synthetic']=False
        self.assertEqual(self.join(allow_synthetic_for_tests=False)['missing_reason'],'synthetic_not_empirical')
        self.assertTrue(self.join()['synthetic'])

    def test_share_adjustment_definition_difference_prevents_exact_match(self):
        f=dict(self.fact,normalized_unit='JPY/share',share_basis='as_reported_not_split_adjusted')
        other=dict(f,jquants_fact_id='synthetic-independent',share_basis='unknown',revision_state='reported_initial_or_unknown')
        r=reconcile_sources(f,other,self.decision,identity_verified=True)
        self.assertIn('definition_difference',r['classifications']);self.assertNotIn('exact_match',r['classifications'])


if __name__ == '__main__': unittest.main()
