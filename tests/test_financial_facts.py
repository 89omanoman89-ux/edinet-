"""Synthetic P3 XML, times, values and IDs. Never open a real local archive in CI."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import unittest
import zipfile

from evidence_core import ContractError
from financial_facts import (DEI, XI, DI, NIL, definitions, extract_candidates,
                             canonicalize, reverse_verify, timestamp, parsed_members)
from financial_views import (reconcile, fact_view, derive_quarter, validate_lineage,
                             revision_roots)
from p3_audit import document_plan
from source_acquisition import sha256

JP = "http://disclosure.edinet-fsa.go.jp/taxonomy/jppfs/2022-11-01/jppfs_cor"
CRP = "http://disclosure.edinet-fsa.go.jp/taxonomy/jpcrp/2022-11-01/jpcrp_cor"
IGP = "http://disclosure.edinet-fsa.go.jp/taxonomy/jpigp/2021-11-01/jpigp_cor"
NOW = "2026-09-18T00:00:00+00:00"


def context(identifier="CurrentYearDuration", start="2021-04-01", end="2022-03-31", standalone=False, instant=False, extra=""):
    dates = f"<x:instant>{end}</x:instant>" if instant else f"<x:startDate>{start}</x:startDate><x:endDate>{end}</x:endDate>"
    dims = '<d:explicitMember dimension="p:ConsolidatedOrNonConsolidatedAxis">p:NonConsolidatedMember</d:explicitMember>' if standalone else ""
    return (f'<x:context id="{identifier}"><x:entity><x:identifier scheme="http://disclosure.edinet-fsa.go.jp">E00001-000</x:identifier></x:entity>'
            f'<x:period>{dates}</x:period><x:scenario>{dims}{extra}</x:scenario></x:context>')


def instance(facts=None, contexts=None, standard="Japan GAAP", consolidated="true", extra_units=""):
    facts = facts if facts is not None else '<p:NetSales contextRef="CurrentYearDuration" unitRef="yen" decimals="-6">123000000</p:NetSales>'
    return (f'<x:xbrl xmlns:x="{XI}" xmlns:d="{DI}" xmlns:p="{JP}" xmlns:c="{CRP}" xmlns:i="{IGP}" xmlns:dei="{DEI}" '
            'xmlns:iso="http://www.xbrl.org/2003/iso4217" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:custom="urn:synthetic:company">'
            + (contexts or context()) + '<x:unit id="yen"><x:measure>iso:JPY</x:measure></x:unit>'
            '<x:unit id="shares"><x:measure>x:shares</x:measure></x:unit>'
            '<x:unit id="per_share"><x:divide><x:unitNumerator><x:measure>iso:JPY</x:measure></x:unitNumerator>'
            '<x:unitDenominator><x:measure>x:shares</x:measure></x:unitDenominator></x:divide></x:unit>'
            + extra_units + f'<dei:EDINETCodeDEI contextRef="CurrentYearDuration">E00001</dei:EDINETCodeDEI>'
            f'<dei:AccountingStandardsDEI contextRef="CurrentYearDuration">{standard}</dei:AccountingStandardsDEI>'
            f'<dei:WhetherConsolidatedFinancialStatementsArePreparedDEI contextRef="CurrentYearDuration">{consolidated}</dei:WhetherConsolidatedFinancialStatementsArePreparedDEI>'
            '<dei:CurrentFiscalYearStartDateDEI contextRef="CurrentYearDuration">2021-04-01</dei:CurrentFiscalYearStartDateDEI>'
            '<dei:CurrentFiscalYearEndDateDEI contextRef="CurrentYearDuration">2022-03-31</dei:CurrentFiscalYearEndDateDEI>'
            + facts + '</x:xbrl>').encode()


def archive(xml, extra=None):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("XBRL/PublicDoc/synthetic.xbrl", xml)
        if extra is not None: z.writestr("XBRL/PublicDoc/other.xbrl", extra)
    return b.getvalue()


def document(doc="S0000001", parent=None, at="2022-06-01T15:01:00+09:00"):
    return {"doc_id": doc, "edinet_code": "E00001", "parentDocID": parent, "public_available_at": at,
        "recorded_at": NOW, "status_events": [], "synthetic": True, "export_allowed": False,
        "original_provider_retrieved_at": "2026-01-01T00:00:00+00:00", "metadata_locators": [], "doc_type": "120"}


def extract(xml=None, d=None, extra=None):
    d = d or document(); data = archive(xml or instance(), extra)
    artifact = {"doc_id": d["doc_id"], "byte_sha256": sha256(data), "byte_count": len(data)}
    config = definitions()
    candidates = extract_candidates(data, artifact, d, config)
    return data, artifact, d, candidates, canonicalize(candidates, config)


class FinancialFactsTests(unittest.TestCase):
    def test_reviewed_modern_exact_qnames_roundtrip(self):
        for version in ('2024-11-01','2025-11-01'):
            # OperatingIncome is observed and explicitly reviewed in both releases.
            raw=instance().replace(b'NetSales',b'OperatingIncome').replace(b'jppfs/2022-11-01/',('jppfs/'+version+'/').encode())
            data,a,d,_,facts=extract(raw)
            self.assertEqual(facts[0]['normalized_value'],'123000000')
            self.assertEqual(reverse_verify(data,a,d,definitions(),facts)['checked_facts'],1)

    def test_reviewed_2016_exact_qname_has_original_roundtrip(self):
        raw=instance().replace(b'jppfs/2022-11-01/',b'jppfs/2016-02-29/')
        data,a,d,_,facts=extract(raw)
        self.assertEqual(facts[0]['normalized_value'],'123000000')
        self.assertEqual(facts[0]['definition_version'],'edinet-financial-v2')
        self.assertEqual(reverse_verify(data,a,d,definitions(),facts)['checked_facts'],1)

    def test_extension_keeps_existing_fact_ids_and_does_not_match_unknown_year(self):
        import json
        from pathlib import Path
        old=json.loads((Path(__file__).parents[1]/'registry/financial_definitions_v1.json').read_bytes())
        data,a,d,_,facts=extract()
        prior=canonicalize(extract_candidates(data,a,d,old),old)
        self.assertEqual([f['fact_id'] for f in facts],[f['fact_id'] for f in prior])
        self.assertEqual(extract(instance().replace(b'2022-11-01/jppfs_cor',b'2999-01-01/jppfs_cor'))[4],[])

    def test_every_value_reverse_resolves_to_bytes_context_unit_and_rule(self):
        data, a, d, _, facts = extract()
        self.assertEqual(reverse_verify(data, a, d, definitions(), facts)["non_null_facts"], 1)
        f = facts[0]
        for key in ("original_qname", "contextRef", "unitRef", "original_unit", "original_value", "normalized_value",
                    "period_start", "period_end", "consolidation", "accounting_standard", "public_available_at",
                    "source_artifact_sha256", "xbrl_member_sha256", "definition_version", "definition_sha256"):
            self.assertIsNotNone(f[key], key)

    def test_reverse_lookup_rejects_changed_value_period_scope_or_locator(self):
        data, a, d, _, facts = extract()
        for key, value in (("normalized_value", "999"), ("contextRef", "fake"), ("period_start", "2000-01-01"),
                           ("consolidation", "standalone"), ("element_index", 0), ("definition_version", "fake")):
            altered = deepcopy(facts); altered[0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ContractError, "source_reverse_lookup_mismatch"):
                reverse_verify(data, a, d, definitions(), altered)

    def test_decimals_is_not_a_unit_multiplier(self):
        f = extract()[4][0]
        self.assertEqual(f["normalized_value"], "123000000")
        self.assertEqual(f["normalized_unit"], "JPY")
        self.assertEqual(f["decimals"], "-6")

    def test_per_share_divide_unit_not_currency_or_share_count(self):
        x = instance('<c:BasicEarningsLossPerShareSummaryOfBusinessResults contextRef="CurrentYearDuration" unitRef="per_share" decimals="2">-1.25</c:BasicEarningsLossPerShareSummaryOfBusinessResults>')
        f = extract(x)[4][0]
        self.assertEqual((f["metric"], f["normalized_value"], f["normalized_unit"]), ("eps_basic_reported", "-1.25", "JPY/share"))
        self.assertIsNotNone(extract(x.replace(b'unitRef="per_share"', b'unitRef="shares"'))[4][0]["missing_reason"])

    def test_unknown_unit_and_inline_scale_fail_closed(self):
        for x in (instance().replace(b'unitRef="yen"', b'unitRef="missing"'),
                  instance().replace(b'decimals="-6"', b'decimals="-6" scale="6"'),
                  instance().replace(b'iso:JPY', b'iso:USD')):
            f = extract(x)[4][0]; self.assertIsNone(f["normalized_value"]); self.assertTrue(f["missing_reason"])

    def test_context_dates_and_instant_are_not_inferred_from_filing_year(self):
        c = context("Prior2YearDuration", "2019-04-01", "2020-03-31")
        f = extract(instance('<p:NetSales contextRef="Prior2YearDuration" unitRef="yen">1</p:NetSales>', c))[4][0]
        self.assertEqual(f["period_end"], "2020-03-31")
        self.assertEqual(f["public_available_at"], document()["public_available_at"])
        f = extract(instance('<p:Assets contextRef="CurrentYearInstant" unitRef="yen">1</p:Assets>', context("CurrentYearInstant", instant=True)))[4][0]
        self.assertEqual(f["instant_date"], "2022-03-31"); self.assertIsNone(f["period_start"])

    def test_context_dei_mismatch_and_reversed_period_are_null(self):
        for c in (context(end="2022-04-01"), context(start="2023-01-01")):
            f = extract(instance(contexts=c))[4][0]
            self.assertIsNone(f["normalized_value"]); self.assertTrue(f["missing_reason"])

    def test_consolidated_standalone_and_ifrs_are_separate(self):
        f = extract()[4][0]; self.assertEqual(f["consolidation"], "consolidated")
        x = instance('<p:NetSales contextRef="CurrentYearDuration_NonConsolidatedMember" unitRef="yen">1</p:NetSales>',
                     context("CurrentYearDuration_NonConsolidatedMember", standalone=True), standard="IFRS")
        f = extract(x)[4][0]
        self.assertEqual((f["consolidation"], f["accounting_standard"]), ("standalone", "JP GAAP"))
        f = extract(instance('<i:OperatingProfitLossIFRS contextRef="CurrentYearDuration" unitRef="yen">-1</i:OperatingProfitLossIFRS>', standard="IFRS"))[4][0]
        self.assertEqual((f["accounting_standard"], f["normalized_value"]), ("IFRS", "-1"))

    def test_unknown_consolidation_and_additional_dimensions_are_null(self):
        for x in (instance(consolidated="false"), instance(contexts=context(extra='<d:explicitMember dimension="custom:SegmentAxis">custom:SegmentMember</d:explicitMember>'))):
            self.assertIsNone(extract(x)[4][0]["normalized_value"])

    def test_detailed_standalone_context_preserves_scope_without_mapping_to_total(self):
        identifier="CurrentYearDuration_NonConsolidatedMember_DetailMember"
        c=context(identifier,standalone=True,extra='<d:explicitMember dimension="custom:DetailAxis">custom:DetailMember</d:explicitMember>')
        x=instance(f'<p:NetSales contextRef="{identifier}" unitRef="yen">1</p:NetSales>',c)
        f=extract(x)[4][0]
        self.assertEqual(f["missing_reason"],"unsupported_dimensions")
        self.assertEqual(f["consolidation"],"standalone");self.assertEqual(f["period_end"],"2022-03-31")
        self.assertEqual(len(f["dimensions"]),2);self.assertIsNone(f["normalized_value"])

    def test_company_specific_similar_tag_is_not_mapped(self):
        _, _, _, candidates, facts = extract(instance().replace(b'p:NetSales', b'custom:NetSales'))
        self.assertFalse(facts); self.assertEqual(candidates[0]["missing_reason"], "unknown_mapping")

    def test_unreviewed_taxonomy_version_not_mapped(self):
        self.assertFalse(extract(instance().replace(JP.encode(), JP.replace("2022-11-01", "2099-01-01").encode()))[4])

    def test_duplicate_context_and_unit_ids_rejected(self):
        for x in (instance(contexts=context()+context()), instance(extra_units='<x:unit id="yen"><x:measure>iso:JPY</x:measure></x:unit>')):
            self.assertIsNone(extract(x)[4][0]["normalized_value"])

    def test_namespace_rebinding_does_not_spoof_scope(self):
        c = context("CurrentYearDuration_NonConsolidatedMember", standalone=True).replace('<d:explicitMember', '<d:explicitMember xmlns:p="urn:synthetic:spoof"')
        x = instance('<p:NetSales contextRef="CurrentYearDuration_NonConsolidatedMember" unitRef="yen">1</p:NetSales>', c)
        self.assertIsNone(extract(x)[4][0]["normalized_value"])

    def test_nil_is_reasoned_null_not_zero(self):
        x = instance().replace(b'>123000000</p:NetSales>', b' xsi:nil="true"></p:NetSales>')
        f = extract(x)[4][0]
        self.assertIsNone(f["normalized_value"]); self.assertEqual(f["missing_reason"], "reported_nil")

    def test_multiple_members_keep_distinct_locators(self):
        data, a, d, _, facts = extract(extra=instance())
        self.assertEqual(len(facts), 2); self.assertNotEqual(facts[0]["fact_id"], facts[1]["fact_id"])
        self.assertEqual(reverse_verify(data, a, d, definitions(), facts)["checked_facts"], 2)

    def test_corruption_hash_and_xml_declarations(self):
        with self.assertRaisesRegex(ContractError, "invalid_zip"): parsed_members(b'bad')
        for declaration in (b'<!DOCTYPE x []>', b'<!ENTITY bad "value">'):
            with self.assertRaisesRegex(ContractError, "xml_rejected"): extract(declaration + instance())
        data, a, d, _, _ = extract(); a["byte_sha256"] = "0"*64
        with self.assertRaisesRegex(ContractError, "source_byte_integrity_failed"): extract_candidates(data,a,d,definitions())

    def test_public_timestamp_precision_is_conservative(self):
        self.assertEqual(timestamp("2022-06-01 15:00"), "2022-06-01T15:01:00+09:00")
        self.assertEqual(timestamp("2022-06-01"), "2022-06-02T00:00:00+09:00")
        self.assertIsNone(timestamp("unknown"))

    def test_future_period_is_not_a_reported_actual(self):
        f = extract(d=document(at="2021-06-01T15:01:00+09:00"))[4][0]
        self.assertIsNone(f["normalized_value"])
        self.assertEqual(f["missing_reason"], "future_period_not_reported_actual")

    def test_invalid_accuracy_and_malformed_divide_units_are_blocked(self):
        self.assertEqual(extract(instance().replace(b'decimals="-6"',b'decimals="guess"'))[4][0]["missing_reason"], "invalid_numeric_accuracy")
        x=instance('<c:BasicEarningsLossPerShareSummaryOfBusinessResults contextRef="CurrentYearDuration" unitRef="per_share">2</c:BasicEarningsLossPerShareSummaryOfBusinessResults>')
        x=x.replace(b'</x:divide>',b'<x:unitDenominator><x:measure>iso:USD</x:measure></x:unitDenominator></x:divide>')
        self.assertEqual(extract(x)[4][0]["missing_reason"],"unit_unknown")


class FinancialViewsTests(unittest.TestCase):
    def setUp(self):
        self.d = document(); self.f = extract(d=self.d)[4][0]
        self.cutoff = datetime.fromisoformat(NOW) + timedelta(days=1)

    def view(self, facts, docs, **kwargs):
        return fact_view(facts, docs, snapshot_cutoff=self.cutoff, allow_synthetic_for_tests=True, **kwargs)

    def revised(self, value="7"):
        d = document("S0000002", "S0000001", "2022-07-01T15:01:00+09:00")
        f = extract(instance().replace(b'123000000', value.encode()), d)[4][0]
        return d, f

    def test_future_comparatives_never_visible_before_filing(self):
        v = self.view([self.f], [self.d], mode="as_of", decision_at=datetime(2021,1,1,tzinfo=timezone.utc))
        self.assertFalse(v["facts"])
        v = self.view([self.f], [self.d], mode="as_of", decision_at=datetime.fromisoformat(self.d["public_available_at"]))
        self.assertFalse(v["facts"])

    def test_as_reported_as_of_latest_restated(self):
        d,f = self.revised(); facts, docs = [self.f,f], [self.d,d]
        self.assertEqual(self.view(facts,docs,mode="as_reported",doc_id=self.d["doc_id"])["facts"], [self.f])
        self.assertEqual(self.view(facts,docs,mode="as_of",decision_at=datetime(2022,6,15,tzinfo=timezone.utc))["facts"], [self.f])
        self.assertEqual(self.view(facts,docs,mode="latest_restated")["facts"], [f])

    def test_null_update_and_missing_update_never_fall_back(self):
        d,f = self.revised(); f["normalized_value"]=None; f["missing_reason"]="reported_nil"
        for facts in ([self.f,f], [self.f]):
            v=self.view(facts,[self.d,d],mode="latest_restated")
            self.assertFalse(v["facts"]); self.assertTrue(v["blocked"])

    def test_withdrawal_never_falls_back(self):
        d,f=self.revised();d["status_events"]=[{"available_at":d["public_available_at"],"blocked_reason":"withdrawn"}]
        v=self.view([self.f,f],[self.d,d],mode="latest_restated")
        self.assertFalse(v["facts"]);self.assertEqual(v["blocked"][0]["reason"],"withdrawn")

    def test_simultaneous_conflicting_status_never_uses_row_order(self):
        d,f=self.revised()
        events=[{"available_at":d["public_available_at"],"blocked_reason":r} for r in (None,"withdrawn")]
        for ordered in (events,list(reversed(events))):
            d["status_events"]=ordered
            v=self.view([self.f,f],[self.d,d],mode="latest_restated")
            self.assertFalse(v["facts"]);self.assertEqual(v["blocked"][0]["reason"],"ambiguous_status_events")

    def test_snapshot_and_system_replay_do_not_backdate_acquisition(self):
        v=self.view([self.f],[self.d],mode="as_of",decision_at=datetime(2023,1,1,tzinfo=timezone.utc),replay="system_replay")
        self.assertFalse(v["facts"]);self.assertTrue(v["blocked"])
        old=datetime(2025,1,1,tzinfo=timezone.utc)
        self.assertFalse(fact_view([self.f],[self.d],mode="latest_restated",snapshot_cutoff=old)["facts"])

    def test_revision_branches_cycles_and_foreign_entity_fail_closed(self):
        d,f=self.revised(); other=dict(d,doc_id="S0000003")
        self.assertFalse(self.view([self.f,f],[self.d,d,other],mode="latest_restated")["facts"])
        d["parentDocID"] = d["doc_id"]
        with self.assertRaises(ContractError):revision_roots([self.d,d])
        d["parentDocID"]=self.d["doc_id"];d["edinet_code"]="E99999"
        with self.assertRaisesRegex(ContractError,"revision_entity_mismatch"):revision_roots([self.d,d])

    def test_conflicting_facts_preserved_and_view_blocked(self):
        b=dict(self.f,fact_id="synthetic-duplicate",normalized_value="999")
        r=reconcile([self.f,b],[self.d]);self.assertEqual(r[0]["classifications"],["conflicting_facts"])
        self.assertFalse(self.view([self.f,b],[self.d],mode="latest_restated")["facts"])
        b["normalized_value"]=self.f["normalized_value"]
        self.assertEqual(reconcile([self.f,b],[self.d])[0]["classifications"],["exact_match"])

    def test_reconciliation_distinguishes_semantics_and_revision(self):
        for key,value,reason in (("consolidation","standalone","scope_difference"),("accounting_standard","IFRS","accounting_standard_difference"),
                                 ("normalized_unit","shares","unit_difference")):
            b=dict(self.f,fact_id="b",**{key:value})
            self.assertIn(reason,reconcile([self.f,b],[self.d])[0]["classifications"])
        d,f=self.revised()
        self.assertIn("restatement_difference",reconcile([self.f,f],[self.d,d])[0]["classifications"])

    def cumulative(self):
        a=dict(self.f, fact_id="current",period_class="cumulative",period_end="2021-09-30",normalized_value="50")
        b=dict(a,fact_id="previous",period_end="2021-06-30",normalized_value="20")
        return a,b

    def test_derived_fact_lineage_and_availability(self):
        a,b=self.cumulative();b["public_available_at"]="2022-08-01T00:00:00+09:00"
        f=derive_quarter(a,b)
        self.assertEqual(f["normalized_value"],"30");self.assertEqual(f["period_start"],"2021-07-01")
        self.assertEqual(f["public_available_at"],b["public_available_at"]);self.assertTrue(f["synthetic"])
        self.assertEqual(validate_lineage([a,b,f],{"current","previous"})["status"],"PASS")
        with self.assertRaisesRegex(ContractError,"orphan_lineage"):validate_lineage([a,f],{"current"})
        f["input_ids"]=[f["fact_id"],"previous"]
        with self.assertRaisesRegex(ContractError,"lineage_cycle"):validate_lineage([a,b,f],{"current","previous"})

    def test_derived_cannot_mix_scope_year_unit_eps_or_vintage(self):
        a,b=self.cumulative()
        for key,value in (("consolidation","standalone"),("period_start","2020-04-01"),("accounting_standard","IFRS"),
                          ("normalized_unit","shares"),("doc_id","S0000002")):
            with self.subTest(key=key),self.assertRaises(ContractError):derive_quarter(a,dict(b,**{key:value}))
        a["metric"]=b["metric"]="eps_basic_reported"
        with self.assertRaisesRegex(ContractError,"metric_not_additive"):derive_quarter(a,b)

    def test_unverified_or_proxy_parent_cannot_promote_derived(self):
        a,b=self.cumulative()
        for changed in (dict(b,verification_state="unverified"),dict(b,representation="proxy"),dict(b,normalized_value=None,missing_reason="missing")):
            f=derive_quarter(a,changed);self.assertIsNone(f["normalized_value"]);self.assertEqual(f["verification_state"],"unverified")

    def test_derived_precision_and_time_tampering(self):
        a,b=self.cumulative();a["normalized_value"]="123456789012345678901234567890.50";b["normalized_value"]="0.25"
        f=derive_quarter(a,b);self.assertEqual(f["normalized_value"],"123456789012345678901234567890.25")
        f["public_available_at"]="2000-01-01T00:00:00+09:00"
        with self.assertRaisesRegex(ContractError,"derived_lineage_mismatch"):validate_lineage([a,b,f],{"current","previous"})

    def test_unknown_unit_is_unresolved_not_an_observed_unit_difference(self):
        b=dict(self.f,fact_id="b",normalized_unit=None,normalized_value=None,missing_reason="unit_unknown")
        self.assertEqual(reconcile([self.f,b],[self.d])[0]["classifications"],["unresolved"])

    def test_synthetic_is_never_empirical_by_default(self):
        self.assertFalse(fact_view([self.f],[self.d],mode="latest_restated",snapshot_cutoff=self.cutoff)["facts"])

    def test_parent_closure_keeps_primary_selection_and_budget(self):
        def r(parent):return {"metadata_events":[{"listing":{"day":"2022-01-01"},"provider_fields":{"parentDocID":parent}}]}
        s={"challenge":["S0000002"],"probability":["S0000003"]};frame={"S0000001":r(None),"S0000002":r("S0000001"),"S0000003":r(None)}
        p=document_plan(s,frame);self.assertEqual(p["primary"],s["challenge"]+s["probability"]);self.assertEqual(p["parent_support"],["S0000001"])
        with self.assertRaisesRegex(ContractError,"parent_closure_budget_exceeded"):document_plan(s,frame,limit=2)


if __name__ == "__main__": unittest.main()
