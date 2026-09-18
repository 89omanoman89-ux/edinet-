"""P2 SYNTHETIC fixtures only. Temporary archives; no network or user raw data."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from evidence_core import ContractError
from filing_catalog import EDINET_COLUMNS
from local_edinet import LocalArchive
import p2_audit as p2
from p2_schema import profile_zip
from source_acquisition import PrivateStore, encoded


def xml(code="E00001", extra="", contexts="", facts=""):
    return (f'<xbrli:xbrl xmlns:xbrli="http://www.xbrl.org/2003/instance" '
        'xmlns:dei="urn:synthetic:jpdei" xmlns:t="urn:synthetic" '
        'xmlns:iso4217="http://www.xbrl.org/2003/iso4217">'
        '<xbrli:context id="c"><xbrli:entity><xbrli:identifier scheme="urn:synthetic">'
        f'{code}</xbrli:identifier></xbrli:entity><xbrli:period><xbrli:instant>2022-01-31'
        '</xbrli:instant></xbrli:period></xbrli:context>'
        '<xbrli:unit id="u"><xbrli:measure>iso4217:JPY</xbrli:measure></xbrli:unit>'
        f'<dei:EDINETCodeDEI contextRef="c">{code}</dei:EDINETCodeDEI>'
        '<dei:AccountingStandardsDEI contextRef="c">Japan GAAP</dei:AccountingStandardsDEI>'
        '<dei:WhetherConsolidatedFinancialStatementsArePreparedDEI contextRef="c">true'
        '</dei:WhetherConsolidatedFinancialStatementsArePreparedDEI>'
        '<t:TestTextBlock contextRef="c">SYNTHETIC TEXT</t:TestTextBlock>'
        f'{extra}{contexts}{facts}</xbrli:xbrl>').encode()


def zipped(*members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for number, member in enumerate(members): z.writestr(f"PublicDoc/test{number}.xbrl", member)
    return buf.getvalue()


class P2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        (self.root / "documents").mkdir(parents=True)
        self.private = Path(self.temp.name) / "private"
        self.store = PrivateStore(self.private / "helper")
        self.archive = LocalArchive(self.root, self.store, provenance_class="synthetic_fixture")
        self.rows = []
        for n in range(1, 7):
            doc, code = f"S{n:07d}", f"E{n:05d}"
            (self.root / "documents" / f"{doc}.zip").write_bytes(zipped(xml(code)))
            row = dict.fromkeys(EDINET_COLUMNS)
            row.update(docID=doc, seqNumber=n, edinetCode=code, secCode="123A0" if n == 1 else None,
                submitDateTime="2022-01-31 15:00", docTypeCode="130" if n == 2 else "120",
                parentDocID="S0000001" if n == 2 else None, filerName=f"SYNTHETIC {n}",
                withdrawalStatus="1" if n == 3 else "0", docInfoEditStatus="0", disclosureStatus="0")
            self.rows.append(row)
        self.metadata()

    def metadata(self):
        path = self.root / "listings" / "2022-01-31" / "documents.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encoded({"metadata": {"status": "200", "parameter": {"date": "2022-01-31"},
            "resultset": {"count": len(self.rows)}}, "results": self.rows}))
        return path

    def select(self, records=None):
        records = records if records is not None else p2.inventory(self.archive)[1]
        return p2.choose(records, p2.metadata_categories(records), 42, 2, 3, 3)

    def run_fixture(self, snapshot="synthetic", **kwargs):
        with redirect_stdout(io.StringIO()):
            return p2.run(self.root, self.private, snapshot, seed=42, probability_count=2,
                challenge_count=3, screen_limit=6, min_entities=3, synthetic=True, **kwargs)

    def test_fixed_seed_same_sample_independent_of_input_order(self):
        _, records = p2.inventory(self.archive)
        self.assertEqual(self.select(records), self.select(dict(reversed(list(records.items())))))

    def test_challenge_categories_preserve_selection_reasons(self):
        _, records = p2.inventory(self.archive)
        cats = p2.metadata_categories(records)
        self.assertIn("alpha_security_code", cats["S0000001"])
        self.assertIn("parent_document", cats["S0000002"])
        self.assertIn("amended_report", cats["S0000002"])
        self.assertIn("unusual_status", cats["S0000003"])
        result = self.select(records)
        self.assertTrue(all(result["challenge_reasons"][d] for d in result["challenge"]))

    def test_probability_and_challenge_disjoint_probability_is_entire_frame_rank(self):
        _, records = p2.inventory(self.archive)
        result = self.select(records)
        self.assertEqual(result["probability"], p2.ranked(records, 42)[:2])
        self.assertFalse(set(result["probability"]) & set(result["challenge"]))

    def test_duplicate_doc_ids_keep_events_and_block_ambiguous_zip(self):
        self.rows.append(dict(self.rows[0], seqNumber=7, docInfoEditStatus="1"))
        self.metadata()
        (self.root / "S0000001.zip").write_bytes(zipped(xml()))
        manifest, records = p2.inventory(self.archive)
        self.assertEqual(manifest["available_doc_id_count"], 6)
        self.assertEqual(len(records["S0000001"]["metadata_events"]), 2)
        audit, _ = p2.audit_document(self.archive, records["S0000001"], {})
        self.assertEqual(audit["local_original_integrity"]["reason"], "identifier_ambiguous")

    def test_insufficient_documents_are_blocked_not_duplicated(self):
        _, records = p2.inventory(self.archive)
        result = p2.choose(records, p2.metadata_categories(records), 42, 5, 5, 10)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("insufficient_documents", result["failures"])
        self.assertEqual(len(set(result["challenge"] + result["probability"])), 6)

    def test_corrupt_zip_is_classified(self):
        (self.root / "documents" / "S0000001.zip").write_bytes(b"SYNTHETIC corrupt ZIP")
        _, records = p2.inventory(self.archive)
        audit, profile = p2.audit_document(self.archive, records["S0000001"], {})
        self.assertIn("invalid_zip", audit["failures"])
        self.assertEqual(profile["parse_status"], "BLOCKED")

    def test_ambiguous_identifier_never_silently_picks_owner(self):
        self.rows.append(dict(self.rows[0], seqNumber=7, edinetCode="E99999"))
        self.metadata()
        _, records = p2.inventory(self.archive)
        audit, _ = p2.audit_document(self.archive, records["S0000001"], {})
        self.assertIn("identifier_ambiguous", audit["failures"])

    def test_multiple_contexts_are_not_duplicate_fact_candidates(self):
        context = ('<xbrli:context id="other"><xbrli:period><xbrli:startDate>2021-01-01'
            '</xbrli:startDate><xbrli:endDate>2021-12-31</xbrli:endDate></xbrli:period></xbrli:context>')
        p = profile_zip(zipped(xml(contexts=context, facts='<t:TestTextBlock contextRef="other">OTHER</t:TestTextBlock>')))
        self.assertEqual(p["context_count"], 2)
        self.assertEqual((p["instant_context_count"], p["duration_context_count"]), (1, 1))
        self.assertTrue(p["same_tag_multiple_contexts"])
        self.assertEqual(p["duplicate_fact_candidate_count"], 0)

    def test_multiple_members_scope_context_ids_per_member(self):
        p = profile_zip(zipped(xml(), xml()))
        self.assertEqual(p["parse_status"], "PASS")
        self.assertEqual(p["xbrl_member_count"], 2)
        self.assertEqual(p["context_count"], 2)
        self.assertNotIn("context_ambiguous", p["failures"])

    def test_missing_daily_metadata_is_separate_from_raw_integrity(self):
        self.metadata().unlink()
        _, records = p2.inventory(self.archive)
        audit, _ = p2.audit_document(self.archive, records["S0000001"], {})
        self.assertEqual(audit["local_daily_metadata_tie"]["reason"], "metadata_missing")
        self.assertEqual(audit["local_original_integrity"]["status"], "PASS")

    def test_missing_third_party_overlap_is_unavailable_not_mismatch(self):
        _, records = p2.inventory(self.archive)
        audit, _ = p2.audit_document(self.archive, records["S0000001"], {})
        self.assertEqual(audit["third_party_tie"]["reason"], "third_party_overlap_not_available")
        self.assertNotIn("third_party_mismatch", audit["failures"])

    def test_real_zip_element_required_for_third_party_pass(self):
        _, records = p2.inventory(self.archive)
        overlap = {"S0000001": {"line_number": 3, "row": {
            "doc_id": "S0000001", "tag": "TestTextBlock", "text": "SYNTHETIC TEXT"}}}
        audit, _ = p2.audit_document(self.archive, records["S0000001"], overlap)
        self.assertEqual(audit["third_party_tie"]["status"], "PASS")
        overlap["S0000001"]["row"]["text"] = "MISMATCH"
        audit, _ = p2.audit_document(self.archive, records["S0000001"], overlap)
        self.assertEqual(audit["third_party_tie"]["reason"], "third_party_mismatch")

    def test_failure_ledger_and_artifacts_have_snapshot_and_code_sha(self):
        result = self.run_fixture()
        output = self.private / "synthetic"
        for name in ("universe_manifest.json", "selected_documents.json", "challenge_sample.json",
            "probability_sample.json", "coverage_summary.json", "source_tie_summary.json"):
            payload = json.loads((output / name).read_bytes())
            self.assertEqual(payload["snapshot_id"], "synthetic")
            self.assertEqual(len(payload["code_sha"]), 64)
        ledger = [json.loads(line) for line in (output / "failure_ledger.jsonl").read_bytes().splitlines()]
        self.assertTrue(all(r["snapshot_id"] == "synthetic" and len(r["code_sha"]) == 64 for r in ledger))
        self.assertTrue(any(r["reason"] == "third_party_overlap_not_available" and r["kind"] == "unavailable" for r in ledger))
        self.assertEqual(result["coverage"]["probability"]["documents"], 2)

    def test_cannot_write_actual_data_under_git_or_input_archive(self):
        git = Path(self.temp.name) / "repo"
        git.mkdir(); (git / ".git").mkdir()
        for out in (git / "data", self.root / "output"):
            with self.subTest(out=out), self.assertRaises(ContractError):
                p2.run(self.root, out, "bad")
            self.assertFalse(out.exists())

    def test_read_only_archive_and_no_snapshot_overwrite(self):
        before = {p.relative_to(self.root).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in self.root.rglob("*") if p.is_file()}
        self.run_fixture()
        with self.assertRaisesRegex(ContractError, "snapshot_already_exists"):
            self.run_fixture()
        after = {p.relative_to(self.root).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
                 for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_xml_rejected_parse_error_and_unsupported_encoding_are_separate(self):
        for content, reason in ((b'<!DOCTYPE x><x/>', "xml_rejected"),
            (b'<!ENTITY x "SYNTHETIC"><x/>', "xml_rejected"), (b'<broken', "xml_parse_failed"),
            (b'<?xml version="1.0" encoding="not-an-encoding"?><x/>', "unsupported_encoding")):
            with self.subTest(reason=reason):
                self.assertIn(reason, profile_zip(zipped(content))["failures"])

    def test_changed_raw_after_frame_is_integrity_failure(self):
        _, records = p2.inventory(self.archive)
        (self.root / "documents" / "S0000001.zip").write_bytes(b"CHANGED")
        audit, _ = p2.audit_document(self.archive, records["S0000001"], {})
        self.assertIn("byte_integrity_failed", audit["failures"])

    def test_structure_cues_do_not_normalize_financial_values(self):
        p = profile_zip(zipped(xml(facts='<t:ProfitLoss contextRef="c" unitRef="u">-1</t:ProfitLoss>')))
        self.assertIn("loss_fact", p2.structural_categories(p))
        self.assertEqual(p["numeric_fact_count"], 1)
        self.assertNotIn("financial_values", p)

    def test_attempt_logs_are_not_daily_metadata_failures(self):
        log = self.root / "listings" / "2022-01-31" / ".attempts" / "synthetic" / "manifest.json"
        log.parent.mkdir(parents=True); log.write_bytes(b"SYNTHETIC LOG NOT DAILY JSON")
        manifest, _ = p2.inventory(self.archive)
        self.assertEqual(manifest["daily_metadata_coverage"]["excluded_auxiliary_json_files"], 1)
        self.assertEqual(manifest["inventory_failures"], [])

    def test_reaudit_new_snapshot_must_keep_original_selection(self):
        original = self.run_fixture()
        path = self.private / "synthetic" / "selected_documents.json"
        again = self.run_fixture("synthetic-v2", frozen_selection=path)
        for key in ("challenge", "probability", "challenge_reasons"):
            self.assertEqual(original["selected"][key], again["selected"][key])

    def test_changed_frame_rejects_frozen_selection_reaudit(self):
        self.run_fixture()
        (self.root / "documents" / "S0000001.zip").write_bytes(b"CHANGED")
        with self.assertRaisesRegex(ContractError, "frozen_selection_frame_changed"):
            self.run_fixture("synthetic-v2", frozen_selection=self.private / "synthetic" / "selected_documents.json")


if __name__ == "__main__": unittest.main()
