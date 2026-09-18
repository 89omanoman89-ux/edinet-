"""Synthetic local metadata closure, missing corrections and temporal graph safety."""
from datetime import datetime, timedelta, timezone
import json
import unittest

from financial_views import fact_view, reconcile
from metadata_gap_audit import snapshot_fingerprints
from revision_series import revision_graph
from source_acquisition import encoded
import test_financial_facts as facts_fixture
import test_metadata_gap_audit as metadata_fixture
import test_p3_audit as audit_fixture


class RevisionInventoryTests(unittest.TestCase):
    setUp = audit_fixture.P3AuditTests.setUp
    audit = audit_fixture.P3AuditTests.audit

    def select_original_only(self):
        (self.p2 / "selected_documents.json").write_bytes(encoded({"challenge": ["S0000001"], "probability": []}))
        for name in ("universe_documents.jsonl", "document_audit.jsonl"):
            rows = [r for r in map(json.loads, (self.p2 / name).read_bytes().splitlines()) if r["doc_id"] == "S0000001"]
            (self.p2 / name).write_bytes(b"".join(encoded(r)+b"\n" for r in rows))

    def output(self, name):
        path = self.base / "output/synthetic-p3" / name
        return list(map(json.loads, path.read_bytes().splitlines())) if name.endswith("jsonl") else json.loads(path.read_bytes())

    def add_child(self, n=3, parent="S0000002", kind="130", with_zip=True, **changes):
        r = metadata_fixture.row(n, parentDocID=parent, docTypeCode=kind, edinetCode="E00001",
                                 submitDateTime="2022-07-01 15:00", **changes)
        path = self.root / "listings/2022-07-01/documents.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.loads(metadata_fixture.daily([r])); payload["metadata"]["parameter"]["date"] = "2022-07-01"
        path.write_bytes(encoded(payload))
        if with_zip: (self.root / "documents" / (r["docID"]+".zip")).write_bytes(facts_fixture.archive(facts_fixture.instance()))

    def test_unselected_child_zip_found_and_classified_revision_support(self):
        self.select_original_only()
        before = {p: snapshot_fingerprints(p) for p in (self.p2, self.root)}
        result = self.audit()
        plan = self.output("audit_plan.json")
        self.assertEqual(plan["primary"], ["S0000001"])
        self.assertEqual(plan["revision_support"], ["S0000002"])
        self.assertEqual(result["non_null_canonical_facts"], 2)
        self.assertEqual(self.output("documents.jsonl")[1]["sample_kind"], "revision_support")
        self.assertEqual(before, {p: snapshot_fingerprints(p) for p in (self.p2, self.root)})

    def test_recursive_child_and_grandchild_have_lineage_and_as_of_boundaries(self):
        self.select_original_only(); self.add_child()
        result = self.audit()
        self.assertEqual(result["revision_support_documents"], 2)
        self.assertEqual(result["revision_max_depth"], 2)
        self.assertEqual(result["revision_as_of_boundaries_checked"], 4)
        self.assertEqual(result["lineage"]["nodes"], 3)
        view = self.output("view_audit.json")
        facts = {f["fact_id"]: f for f in self.output("canonical_facts.jsonl")}
        self.assertEqual({facts[f]["doc_id"] for f in view["latest_restated_fact_ids"]}, {"S0000003"})
        for v in self.output("revision_as_of_audit.jsonl"):
            expected = {("S0000002", "at_exclusive_boundary"): "S0000001",
                        ("S0000002", "after_boundary"): "S0000002",
                        ("S0000003", "at_exclusive_boundary"): "S0000002",
                        ("S0000003", "after_boundary"): "S0000003"}
            self.assertEqual({facts[f]["doc_id"] for f in v["fact_ids"]}, {expected[v["revision_doc_id"], v["boundary"]]})

    def test_metadata_only_child_missing_zip_is_kept_and_no_fallback(self):
        self.select_original_only(); (self.root / "documents/S0000002.zip").unlink()
        result = self.audit()
        self.assertEqual(result["failure_counts"]["revision_raw_missing"], 1)
        self.assertFalse(self.output("view_audit.json")["latest_restated_fact_ids"])
        states = self.output("revision_as_of_audit.jsonl")
        self.assertTrue(states[0]["fact_ids"]); self.assertFalse(states[1]["fact_ids"])
        self.assertIn("revision_raw_missing", {r["reason"] for r in states[1]["blocked"]})

    def test_missing_middle_zip_does_not_hide_a_later_available_revision(self):
        self.select_original_only(); self.add_child(); (self.root / "documents/S0000002.zip").unlink()
        result = self.audit()
        self.assertEqual(result["documents_audited"], 3)
        self.assertEqual(result["failure_counts"]["revision_raw_missing"], 1)
        self.assertTrue(self.output("view_audit.json")["latest_restated_fact_ids"])

    def test_confirmation_is_not_mistaken_for_correction(self):
        self.select_original_only(); self.add_child(parent="S0000001", kind="135")
        self.assertEqual(self.audit()["documents_audited"], 2)
        excluded = self.output("audit_plan.json")["excluded_non_revision_relations"]
        self.assertEqual(excluded[0]["reason"], "non_revision_document_type")

    def test_bad_daily_metadata_blocks_claim_of_complete_revision_inventory(self):
        (self.root / "listings/bad.json").write_bytes(b'{}')
        result = self.audit()
        self.assertEqual(result["revision_metadata_inventory"]["status"], "BLOCKED")
        self.assertFalse(self.output("view_audit.json")["latest_restated_fact_ids"])
        self.assertIn("revision_metadata_inventory_incomplete", result["failure_counts"])

    def test_branch_is_saved_to_failure_ledger_without_crashing_audit(self):
        self.select_original_only(); self.add_child(parent="S0000001")
        result = self.audit()
        self.assertEqual(result["revision_series_blocked"], 1)
        self.assertFalse(self.output("view_audit.json")["latest_restated_fact_ids"])
        self.assertIn("ambiguous_revision_branches", {x["reason"] for x in self.output("failure_ledger.jsonl")})

    def test_unknown_child_type_is_blocked_instead_of_silently_excluded(self):
        self.select_original_only(); self.add_child(kind="999")
        result = self.audit()
        self.assertEqual(result["documents_audited"], 3)
        self.assertIn("document_type_out_of_scope", result["failure_counts"])
        self.assertFalse(self.output("view_audit.json")["latest_restated_fact_ids"])

    def test_conflicting_submission_time_cannot_hide_a_possibly_earlier_child(self):
        self.select_original_only()
        r = metadata_fixture.row(2, edinetCode="E00001", docTypeCode="130", parentDocID="S0000001",
                                 submitDateTime="2022-05-01 15:00")
        path = self.root / "listings/conflict.json"; path.write_bytes(metadata_fixture.daily([r]))
        self.audit()
        d = next(d for d in self.output("documents.jsonl") if d["doc_id"] == "S0000002")
        self.assertIsNone(d["public_available_at"])
        self.assertIn("revision_submit_time_ambiguous", d["revision_conflicts"])
        self.assertFalse(self.output("view_audit.json")["latest_restated_fact_ids"])


class RevisionViewTests(unittest.TestCase):
    def setUp(self):
        self.docs = [facts_fixture.document(), facts_fixture.document("S0000002", "S0000001", "2022-07-01T15:01:00+09:00"),
                     facts_fixture.document("S0000003", "S0000002", "2022-08-01T15:01:00+09:00")]
        self.facts = [facts_fixture.extract(d=d)[4][0] for d in self.docs]

    def view(self, mode="latest_restated", **changes):
        return fact_view(self.facts, self.docs, mode=mode, snapshot_cutoff=datetime(2026, 9, 19, tzinfo=timezone.utc),
                         allow_synthetic_for_tests=True, **changes)

    def test_multistage_as_of_before_at_and_after_each_revision(self):
        for i in (1, 2):
            at = datetime.fromisoformat(self.docs[i]["public_available_at"])
            self.assertEqual(self.view("as_of", decision_at=at)["facts"], [self.facts[i-1]])
            self.assertEqual(self.view("as_of", decision_at=at+timedelta(microseconds=1))["facts"], [self.facts[i]])
        self.assertEqual(self.view()["facts"], [self.facts[2]])

    def test_future_branch_is_hidden_then_blocks(self):
        self.docs[2]["parentDocID"] = "S0000001"
        self.assertEqual(self.view("as_of", decision_at=datetime(2022,7,15,tzinfo=timezone.utc))["facts"], [self.facts[1]])
        self.assertFalse(self.view()["facts"])
        self.assertIn("ambiguous_revision_branches", {x["reason"] for x in self.view()["blocked"]})

    def test_cycle_is_blocked_not_an_exception_and_reconciliation_unresolved(self):
        self.docs[0]["parentDocID"] = "S0000003"
        self.assertFalse(self.view()["facts"])
        self.assertIn("revision_cycle", {x["reason"] for x in self.view()["blocked"]})
        self.assertTrue(all("unresolved" in r["classifications"] for r in reconcile(self.facts, self.docs)))

    def test_entity_mismatch_blocks_series_but_not_before_future_child(self):
        self.docs[2]["edinet_code"] = "E99999"
        self.assertFalse(self.view()["facts"])
        self.assertIn("revision_entity_mismatch", {x["reason"] for x in self.view()["blocked"]})
        self.assertEqual(self.view("as_of", decision_at=datetime(2022,7,15,tzinfo=timezone.utc))["facts"], [self.facts[1]])

    def test_unknown_child_time_poison_series_instead_of_using_old_value(self):
        self.docs[2]["public_available_at"] = None
        self.assertFalse(self.view()["facts"])
        self.assertIn("unknown_availability", {x["reason"] for x in self.view()["blocked"]})

    def test_conflicting_metadata_parent_preserves_all_edges_and_blocks(self):
        self.docs[2]["parentDocIDs"] = ["S0000001", "S0000002"]
        self.assertFalse(self.view()["facts"])
        self.assertIn("revision_parent_ambiguous", {x["reason"] for x in self.view()["blocked"]})

    def test_missing_parent_and_unrelated_series_remain_separate(self):
        self.docs[1]["parentDocID"] = "S0000099"
        self.assertEqual(self.view()["facts"], [self.facts[0]])
        self.assertIn("revision_parent_missing", {x["reason"] for x in self.view()["blocked"]})
        self.assertEqual(len(revision_graph(self.docs)["components"]), 2)


if __name__ == "__main__": unittest.main()
