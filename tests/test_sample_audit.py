"""SYNTHETIC fixtures only. No EDINET key or network is used by these tests."""
from contextlib import ExitStack, redirect_stdout
from datetime import date, datetime, timezone
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from evidence_core import ContractError
from filing_catalog import EDINET_COLUMNS
import sample_audit as audit
from source_acquisition import Acquirer, Fetch, PrivateStore, encoded, sha256


class SampleAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = PrivateStore(Path(self.temp.name) / "private")
        self.row = dict(company_name="SYNTHETIC", document_name="TEST", doc_id="S0000001",
            sec_code=None, edinet_code="E00001", period_start="2020-11-01", period_end="2021-10-31",
            submit_date="2022-01-31", JCN=None, tag="TestTextBlock", text="SYNTHETIC TEXT",
            url="https://example.invalid/synthetic")
        self.task = Fetch("synthetic", "https://api.edinet-fsa.go.jp/api/v2/documents/S0000001?type=1",
                          None, "synthetic-run", audit.TERMS, doc_id="S0000001",
                          interface_version=audit.API_SPEC_VERSION)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("PublicDoc/synthetic.xbrl",
                '<root xmlns:t="urn:synthetic"><t:TestTextBlock contextRef="test">'
                '&lt;p&gt;SYNTHETIC TEXT&lt;/p&gt;</t:TestTextBlock></root>')
        self.zip_bytes = buf.getvalue()

    def original(self):
        return Acquirer(self.store, sleep=lambda _: None,
                        send=lambda *args: (200, {}, self.zip_bytes)).fetch(self.task)

    def test_2014_outside_retention_not_auth_failure(self):
        result = audit.retention_check("2014-06-25", date(2026, 9, 18))
        self.assertEqual(result["reason"], "outside_official_retention_window")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(audit.retention_check("2022-01-31", date(2026, 9, 18))["status"], "PASS")
        self.assertEqual(audit.retention_check("2016-09-18", date(2026, 9, 18))["reason"],
                         "retention_boundary_requires_review")

    def test_positive_original_tie_records_locator_and_schema(self):
        result = audit.tie_original(self.store, self.row, self.original())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["locators"][0]["tag"], "{urn:synthetic}TestTextBlock")
        self.assertEqual(result["locators"][0]["context_ref"], "test")
        self.assertTrue(result["locators"][0]["member_sha256"])
        self.assertEqual(result["original_schema_profile"]["format"], "zip/xbrl")

    def test_doc_id_mismatch_cannot_pass(self):
        result = audit.tie_original(self.store, dict(self.row, doc_id="S0000002"), self.original())
        self.assertEqual(result["reason"], "original_document_mismatch")

    def test_tag_and_text_mismatch_cannot_pass(self):
        original = self.original()
        for change in ({"tag": "OtherBlock"}, {"text": "DIFFERENT TEXT"}):
            with self.subTest(change=change):
                result = audit.tie_original(self.store, dict(self.row, **change), original)
                self.assertEqual(result["reason"], "original_tag_text_not_matched")

    def test_raw_corruption_blocks_tie_and_checkpoint_reuse(self):
        original = self.original()
        (self.store.root / "raw" / original["byte_sha256"]).write_bytes(b"CORRUPTED SYNTHETIC")
        with self.assertRaises(ContractError): audit.tie_original(self.store, self.row, original)
        with self.assertRaises(ContractError): self.original()

    def simulated_run(self, *, year=2022, key=True):
        row = dict(self.row, submit_date="2014-06-25") if year == 2014 else self.row
        sample = encoded(row) + b"\n"
        metadata_row = dict.fromkeys(EDINET_COLUMNS)
        metadata_row.update(seqNumber=1, docID=row["doc_id"], withdrawalStatus="0",
                            docInfoEditStatus="0", disclosureStatus="0")
        metadata = encoded({"metadata": {"status": "200", "resultset": {"count": 1}},
                            "results": [metadata_row]})
        calls = []
        def send(url, headers, limit, authenticated):
            calls.append(url.split("?")[0])  # Never store even the synthetic key in logs.
            if ".jsonl" in url:
                return 206, {"Content-Range": f"bytes 0-{len(sample)-1}/{len(sample)}"}, sample
            if "/documents/" in url:
                return 200, {}, self.zip_bytes
            if "/documents.json" in url:
                return 200, {}, metadata
            return 200, {}, b"SYNTHETIC DOCS"
        def factory(store, **kwargs):
            return Acquirer(store, send=send, sleep=lambda _: None,
                            secret_getter=lambda _: "synthetic-key" if key else None)
        with ExitStack() as stack:
            stack.enter_context(patch.object(audit, "Acquirer", factory))
            stack.enter_context(patch.object(audit, "REVIEWED_CARD", sha256(b"SYNTHETIC DOCS")))
            stack.enter_context(patch.object(audit, "REVIEWED_SPEC", sha256(b"SYNTHETIC DOCS")))
            clock = stack.enter_context(patch.object(audit, "datetime"))
            clock.now.return_value = datetime(2026, 9, 18, tzinfo=timezone.utc)
            stack.enter_context(redirect_stdout(io.StringIO()))
            result = audit.run_twice(self.store.root, "test-run", "2022-01-31", "SYNTHETIC_KEY", sample_year=year)
        return result, calls

    def test_same_snapshot_full_offline_driver_reuses_all_checkpoints(self):
        (report, resume), calls = self.simulated_run()
        self.assertEqual(resume["status"], "PASS")
        self.assertEqual(resume["first"]["network_attempts"], 6)
        self.assertEqual(resume["second"]["network_attempts"], 0)
        self.assertEqual(resume["second"]["cache_hits"], 6)
        self.assertEqual(len(calls), 6)
        self.assertEqual(report["sample"]["file"], "yuho-2022.jsonl")
        self.assertEqual(report["sources"][0]["source_tied"]["status"], "PASS")
        self.assertEqual(report["sources"][1]["source_tied"]["status"], "PASS")
        self.assertFalse(report["sources"][0]["export_allowed"])
        self.assertEqual(report["sources"][0]["rights_reviewed"]["status"], "BLOCKED")

    def test_historical_route_does_not_request_original_zip(self):
        (report, _), calls = self.simulated_run(year=2014)
        self.assertFalse(any("/documents/" in url for url in calls))
        self.assertEqual(report["sources"][0]["source_tied"]["reason"], "outside_official_retention_window")
        self.assertIsNone(report["artifacts"]["official_original"])

    def test_missing_secret_retains_blocked_while_public_cache_passes(self):
        (report, resume), calls = self.simulated_run(key=False)
        self.assertEqual(resume["status"], "PASS")
        self.assertEqual(len(calls), 4)
        self.assertEqual(report["sources"][0]["source_tied"]["reason"], "approved_secret_not_configured")
        self.assertEqual(report["sources"][1]["file_fetched"]["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
