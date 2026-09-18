"""Synthetic archives only: no user files, credentials or external network."""
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from evidence_core import ContractError
from filing_catalog import EDINET_COLUMNS
from local_edinet import LocalArchive, audit_local, select_sample
from original_tie import compare_zip
import sample_audit
from source_acquisition import Acquirer, PrivateStore, encoded, sha256


class LocalArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.store = PrivateStore(Path(self.temp.name) / "audit")
        self.archive = LocalArchive(self.root, self.store, provenance_class="synthetic_fixture")
        self.row = dict(company_name="SYNTHETIC", document_name="TEST", doc_id="S0000001",
            sec_code=None, edinet_code="E00001", period_start="2020-11-01", period_end="2021-10-31",
            submit_date="2022-01-31", JCN=None, tag="TestTextBlock", text="SYNTHETIC TEXT",
            url="https://example.invalid/synthetic")
        with zipfile.ZipFile(self.root / "S0000001.zip", "w") as archive:
            archive.writestr("PublicDoc/test.xbrl", '<root xmlns:t="urn:synthetic">'
                '<t:TestTextBlock contextRef="ctx">SYNTHETIC TEXT</t:TestTextBlock></root>')

    def observe(self):
        return self.archive.observe("S0000001.zip", doc_id="S0000001")

    def test_local_zip_positive_records_both_text_hashes(self):
        artifact = self.observe()
        result = compare_zip(self.archive.read(artifact), self.row, artifact)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["numad_text_sha256"], sha256(self.row["text"].encode()))
        self.assertEqual(result["locators"][0]["original_text_sha256"], result["numad_text_sha256"])
        self.assertEqual(result["locators"][0]["context_ref"], "ctx")
        self.assertIsNone(artifact["original_provider_retrieved_at"])
        self.assertEqual(artifact["original_provider_retrieved_at_missing_reason"], "original_acquisition_log_not_available")
        self.assertEqual(artifact["provenance_class"], "synthetic_fixture")

    def test_local_zip_document_id_mismatch(self):
        with self.assertRaisesRegex(ContractError, "document_id_mismatch"):
            self.archive.observe("S0000001.zip", doc_id="S0000002")
        artifact = self.observe()
        self.assertEqual(compare_zip(self.archive.read(artifact), dict(self.row, doc_id="S0000002"),
                                     artifact)["reason"], "original_document_mismatch")

    def test_matching_tag_different_text_is_blocked(self):
        artifact = self.observe()
        result = compare_zip(self.archive.read(artifact), dict(self.row, text="OTHER"), artifact)
        self.assertEqual(result["reason"], "original_tag_text_not_matched")

    def test_corrupt_zip_is_blocked(self):
        (self.root / "S0000001.zip").write_bytes(b"SYNTHETIC INVALID ZIP")
        artifact = self.observe()
        self.assertEqual(compare_zip(self.archive.read(artifact), self.row, artifact)["reason"], "original_parse_failed")

    def test_changed_bytes_fail_saved_sha_validation(self):
        artifact = self.observe()
        (self.root / "S0000001.zip").write_bytes(b"TAMPERED SYNTHETIC")
        with self.assertRaisesRegex(ContractError, "byte_integrity_failure"):
            self.archive.read(artifact)

    def test_git_checkout_and_archive_output_root_rejected(self):
        with self.assertRaises(ContractError): LocalArchive(self.root, PrivateStore(self.root / "output"))
        (self.root / ".git").write_text("synthetic worktree marker")
        with self.assertRaisesRegex(ContractError, "inside_git_checkout"):
            LocalArchive(self.root, self.store)

    def test_cli_rejects_output_inside_source_before_creating_it(self):
        output = self.root / "must-not-be-created"
        with self.assertRaises(ContractError):
            sample_audit.run(output, "test", "2022-01-31", edinet_local_root=self.root)
        self.assertFalse(output.exists())

    def test_read_only_bytes_names_mtime_and_no_raw_copy(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        result = audit_local(self.archive, self.row, self.archive.zip_index())
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        self.assertEqual(before, after)
        self.assertEqual(result["local_official_original_tied"]["status"], "PASS")
        self.assertFalse((self.store.root / "raw").exists())
        self.assertNotIn(str(self.root), encoded(result).decode())

    def test_reaudit_reuses_identical_observation_manifest(self):
        first = self.observe()
        second = self.observe()
        self.assertEqual(encoded(first), encoded(second))
        self.assertEqual(len(list((self.store.root / "local_manifests").glob("*.json"))), 1)

    def test_local_tie_never_satisfies_live_api_guard(self):
        artifact = self.observe()
        self.assertEqual(compare_zip(self.archive.read(artifact), self.row, artifact)["status"], "PASS")
        self.assertEqual(sample_audit.tie_original(self.store, self.row, artifact)["reason"], "local_archive_not_live_api")

    def test_logged_hash_checked_and_timestamp_not_inferred_from_mtime(self):
        original = self.observe()
        log = {"doc_id": "S0000001", "sha256": original["byte_sha256"], "bytes": original["byte_count"],
               "source": "EDINET official API v2", "endpoint": "/api/v2/documents/S0000001",
               "http_status": 200, "retrieved_at": "2023-01-01T00:00:00+00:00"}
        path = self.root / "S0000001.manifest.json"
        path.write_bytes(encoded(log))
        self.assertEqual(self.observe()["original_provider_retrieved_at"], log["retrieved_at"])
        path.write_bytes(encoded(dict(log, sha256="0" * 64)))
        with self.assertRaisesRegex(ContractError, "log_byte_integrity_failure"): self.observe()

    def test_missing_and_matching_daily_metadata(self):
        self.assertEqual(self.archive.daily_metadata(self.row)["reason"], "local_daily_metadata_not_available")
        row = dict.fromkeys(EDINET_COLUMNS)
        row.update(seqNumber=1, docID="S0000001", withdrawalStatus="0", docInfoEditStatus="0", disclosureStatus="0")
        (self.root / "2022-01-31.json").write_bytes(encoded({"metadata": {"status": "200",
            "parameter": {"date": "2022-01-31"}, "resultset": {"count": 1}}, "results": [row]}))
        self.assertEqual(self.archive.daily_metadata(self.row)["status"], "PASS")

    def test_selection_prefers_first_then_sorted_intersection_without_testing_ties(self):
        first = encoded(self.row) + b"\n"
        self.assertEqual(select_sample(first, {"S0000001": []})[2]["line_number"], 1)
        full = first + encoded(dict(self.row, doc_id="S0000003")) + b"\n" + encoded(dict(self.row, doc_id="S0000002")) + b"\n"
        selected = select_sample(first, {"S0000002": [], "S0000003": []}, full)
        self.assertEqual(selected[0]["doc_id"], "S0000002")
        self.assertEqual(selected[2]["line_number"], 3)
        self.assertEqual(selected[2]["intersection_doc_ids"], ["S0000002", "S0000003"])

    def test_live_blocked_does_not_prevent_or_get_promoted_by_local_pass(self):
        sample = encoded(self.row) + b"\n"
        def send(url, *args):
            self.assertNotIn("api.edinet-fsa.go.jp", url)
            if ".jsonl" in url:
                return 206, {"Content-Range": f"bytes 0-{len(sample)-1}/{len(sample)}"}, sample
            return 200, {}, b"SYNTHETIC DOCS"
        def factory(store, **kwargs):
            return Acquirer(store, send=send, sleep=lambda _: None, secret_getter=lambda _: None)
        with ExitStack() as stack:
            stack.enter_context(patch.object(sample_audit, "Acquirer", factory))
            stack.enter_context(redirect_stdout(io.StringIO()))
            report, resume = sample_audit.run_twice(self.store.root, "test", "2022-01-31",
                edinet_local_root=self.root)
        self.assertEqual(report["local_archive"]["local_official_original_tied"]["status"], "PASS")
        self.assertEqual(report["routes"]["live_official_metadata_fetch"]["status"], "BLOCKED")
        self.assertEqual(report["routes"]["live_official_original_fetch"]["status"], "BLOCKED")
        self.assertEqual(resume["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
