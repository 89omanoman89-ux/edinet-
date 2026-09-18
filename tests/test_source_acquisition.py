"""All payloads, identifiers and values in this file are SYNTHETIC fixtures."""
from dataclasses import replace
from datetime import date, datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import URLError
import zipfile

from evidence_core import ContractError
from filing_catalog import (EDINET_COLUMNS, Entity, Security, IdentityVersion,
    edinet_metadata, numad_sample, resolve_identifier, save_filings, save_master)
from sample_audit import reviewed_docs, tie_original
from source_acquisition import Acquirer, Fetch, PrivateStore, audit, encoded, gate, safe_uri

NOW = "2026-01-01T00:00:00+00:00"
TASK = Fetch("synthetic", "https://example.invalid/sample", "test-v1", "test-run",
             "https://example.invalid/terms")


def numad():
    return dict(company_name="SYNTHETIC", document_name="TEST", doc_id="S0000001",
        sec_code="123A0", edinet_code="E00001", period_start="2023-01-01",
        period_end="2023-12-31", submit_date="2024-03-01", JCN=None,
        tag="TestTextBlock", text="SYNTHETIC TEXT", url="https://example.invalid/original")


def filing(**changes):
    row = dict.fromkeys(EDINET_COLUMNS)
    row.update(seqNumber=1, docID="S0000001", edinetCode="E00001", issuerEdinetCode="E00002",
               subjectEdinetCode="E00003", secCode="123A0", withdrawalStatus="0",
               docInfoEditStatus="0", disclosureStatus="0")
    row.update(changes)
    return row


def metadata(rows):
    return encoded({"metadata": {"status": "200", "resultset": {"count": len(rows)}}, "results": rows})


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = PrivateStore(Path(self.temp.name) / "private")
        self.calls, self.sleeps = [], []

    def client(self, responses, **kwargs):
        def send(*args):
            self.calls.append(args)
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response
        return Acquirer(self.store, send=send, sleep=self.sleeps.append, now=lambda: NOW, **kwargs)

    def fetch_bytes(self, data, task=TASK):
        return self.client([(200, {"Content-Length": str(len(data))}, data)]).fetch(task)

    def test_resume_preserves_manifest_and_retrieval_time(self):
        first = self.fetch_bytes(b"SYNTHETIC")
        second = self.client([]).fetch(TASK)
        self.assertEqual(encoded(first), encoded(second))
        self.assertEqual(len(self.calls), 1)

    def test_new_snapshot_cannot_overwrite_changed_bytes(self):
        first = self.fetch_bytes(b"first")
        second = self.fetch_bytes(b"second", replace(TASK, snapshot="new"))
        self.assertNotEqual(first["byte_sha256"], second["byte_sha256"])
        self.assertEqual(self.store.read_raw(first), b"first")

    def test_immutable_path_conflict(self):
        self.store.publish("test/a", b"a")
        with self.assertRaises(ContractError):
            self.store.publish("test/a", b"b")

    def test_interruption_after_raw_before_checkpoint(self):
        publish = self.store.publish
        def interrupt(path, data):
            if path.startswith("completed/"):
                raise KeyboardInterrupt()
            return publish(path, data)
        self.store.publish = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.fetch_bytes(b"original")
        raw = list((self.store.root / "raw").iterdir())[0].read_bytes()
        self.store.publish = publish
        result = self.fetch_bytes(b"original")
        self.assertEqual(self.store.read_raw(result), raw)

    def test_interrupted_transfer_does_not_commit_partial_bytes(self):
        with self.assertRaises(KeyboardInterrupt):
            self.client([KeyboardInterrupt()]).fetch(TASK)
        self.assertFalse((self.store.root / "completed").exists())
        self.assertEqual(self.fetch_bytes(b"complete")["status"], "FETCHED")

    def test_corrupt_cache_fails_closed(self):
        result = self.fetch_bytes(b"good")
        (self.store.root / "raw" / result["byte_sha256"]).write_bytes(b"bad")
        with self.assertRaises(ContractError):
            self.client([]).fetch(TASK)

    def test_repo_and_git_ancestor_and_path_escape_rejected(self):
        repo = Path(self.temp.name) / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        for root in (repo, repo / "raw"):
            with self.assertRaises(ContractError):
                PrivateStore(root)
        with self.assertRaises(ContractError):
            PrivateStore(repo / "raw", repository=repo)
        with self.assertRaises(ContractError):
            self.store.publish("../escape", b"x")

    def test_missing_secret_is_blocked_without_network(self):
        task = replace(TASK, url="https://api.edinet-fsa.go.jp/api/v2/documents.json", secret_name="TEST_SECRET")
        result = self.client([]).fetch(task)
        self.assertEqual(result["missing_reason"], "approved_secret_not_configured")
        self.assertIsNone(result["byte_sha256"])
        self.assertEqual(self.calls, [])

    def test_secrets_do_not_enter_url_error_headers_or_raw(self):
        task = replace(TASK, url="https://api.edinet-fsa.go.jp/api/v2/documents.json?type=2",
                       secret_name="TEST_SECRET")
        client = self.client([(200, {"Content-Type": "SECRET"}, b"valid")], secret_getter=lambda n: "SECRET")
        result = client.fetch(task)
        self.assertEqual(result["missing_reason"], "credential_echo_rejected")
        self.assertNotIn("SECRET", encoded(result).decode().replace("TEST_SECRET", ""))
        self.assertNotIn("HIDDEN", encoded(result).decode())
        self.assertFalse((self.store.root / "raw").exists())

    def test_transport_error_does_not_persist_exception(self):
        result = self.client([URLError("SECRET")] * 3).fetch(TASK)
        self.assertEqual(result["missing_reason"], "transport_failed")
        self.assertNotIn("SECRET", encoded(result).decode())
        self.assertEqual(len(result["attempts"]), 3)

    def test_retry_after_and_rate_limit(self):
        result = self.client([(429, {"Retry-After": "3"}, b""), (503, {}, b""), (200, {}, b"ok")]).fetch(TASK)
        self.assertEqual(result["status"], "FETCHED")
        self.assertEqual(self.sleeps, [1.0, 3.0, 1.0, 2, 1.0])

    def test_long_retry_after_deferred(self):
        result = self.client([(429, {"Retry-After": "120"}, b"")]).fetch(TASK)
        self.assertEqual(result["missing_reason"], "retry_after_deferred")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.client([]).fetch(TASK), result)

    def test_http_date_retry_after(self):
        result = self.client([(503, {"Retry-After": "Thu, 01 Jan 2026 00:00:05 GMT"}, b""),
                              (200, {}, b"ok")]).fetch(TASK)
        self.assertEqual(result["status"], "FETCHED")
        self.assertIn(5, self.sleeps)

    def test_failed_request_can_resume_but_error_body_never_saved(self):
        bad = self.client([(403, {}, b"SECRET")]).fetch(TASK)
        self.assertEqual(bad["missing_reason"], "authentication_or_access_denied")
        self.assertFalse((self.store.root / "raw").exists())
        self.assertEqual(self.fetch_bytes(b"ok")["status"], "FETCHED")

    def test_size_partial_and_empty_responses_blocked(self):
        for status, headers, data, reason in [
            (200, {}, b"", "empty_response"),
            (200, {"Content-Length": "5"}, b"x", "incomplete_response"),
            (200, {"Content-Length": "x"}, b"x", "invalid_content_length"),
            (206, {}, b"x", "unexpected_partial_response"),
            (200, {}, b"12345", "size_limit_exceeded"),
            (200, {"Content-Encoding": "gzip"}, b"x", "unexpected_content_encoding")]:
            with self.subTest(reason=reason):
                result = self.client([(status, headers, data)]).fetch(replace(TASK, max_bytes=4))
                self.assertEqual(result["missing_reason"], reason)

    def test_range_must_match_requested_prefix(self):
        task = replace(TASK, range_end=2, max_bytes=3)
        bad = self.client([(200, {}, b"abc")]).fetch(task)
        self.assertEqual(bad["missing_reason"], "invalid_sample_range")
        good = self.client([(206, {"Content-Range": "bytes 0-2/10"}, b"abc")]).fetch(task)
        self.assertEqual(good["byte_count"], 3)

    def test_url_and_credential_destination_validation(self):
        self.assertEqual(safe_uri("https://example.invalid/x?date=2026-01-01&token=x#secret"),
                         "https://example.invalid/x?date=2026-01-01")
        for url in ("http://example.invalid/", "https://u:p@example.invalid/"):
            with self.assertRaises(ContractError): safe_uri(url)
        with self.assertRaises(ContractError): replace(TASK, secret_name="KEY").identity()
        with self.assertRaises(ContractError): replace(TASK, url=TASK.url + "?token=SECRET").identity()

    def test_download_is_not_documentation_review(self):
        artifact = self.fetch_bytes(b"unreviewed documentation")
        self.assertEqual(reviewed_docs(artifact, "a" * 64)["status"], "BLOCKED")

    def test_audit_does_not_promote_download_to_source_tied_or_rights(self):
        result = audit("test", docs=gate(), artifact=self.fetch_bytes(b"test"), schema=gate(),
                       tie=gate("original_missing"), rights=gate("rights_unknown"))
        self.assertEqual(result["file_fetched"]["status"], "PASS")
        self.assertEqual(result["source_tied"]["status"], "BLOCKED")
        self.assertFalse(result["production_approved"])

    def test_original_requires_bytes_id_and_matching_tag_text(self):
        row = numad()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("PublicDoc/test.xbrl", "<root><TestTextBlock contextRef='test'>SYNTHETIC TEXT</TestTextBlock></root>")
        task = replace(TASK, url="https://api.edinet-fsa.go.jp/api/v2/documents/S0000001?type=1", doc_id="S0000001")
        artifact = self.fetch_bytes(buf.getvalue(), task)
        self.assertEqual(tie_original(self.store, row, artifact)["status"], "PASS")
        self.assertEqual(tie_original(self.store, dict(row, text="OTHER"), artifact)["status"], "BLOCKED")
        self.assertEqual(tie_original(self.store, row, dict(artifact, doc_id="S0000002"))["status"], "BLOCKED")

    def test_corrections_withdrawals_and_absence_keep_history(self):
        initial = [filing()]
        first = save_filings(self.store, initial, self.fetch_bytes(metadata(initial)))
        changed = [filing(withdrawalStatus="2", edinetCode=None, secCode=None),
                   filing(seqNumber=2, docID="S0000002", parentDocID="S0000001")]
        second = save_filings(self.store, changed, self.fetch_bytes(metadata(changed), replace(TASK, snapshot="new")))
        self.assertIn("withdrawalStatus", second["changes"][0]["fields"])
        self.assertEqual(second["filings"][1]["parent_doc_id"], "S0000001")
        self.assertEqual(first["filings"][0]["provider_fields"]["withdrawalStatus"], "0")
        third = save_filings(self.store, [], self.fetch_bytes(metadata([]), replace(TASK, snapshot="empty")))
        self.assertTrue(all(c["kind"] == "absent_from_snapshot" for c in third["changes"]))
        self.assertEqual(len(list((self.store.root / "filings").glob("*.json"))), 3)
        restored = save_filings(self.store, initial, self.fetch_bytes(metadata(initial), replace(TASK, snapshot="restored")))
        self.assertEqual(restored["revision"], 3)
        self.assertNotEqual(restored["acquisition_task_id"], first["acquisition_task_id"])


class SchemaAndIdentityTests(unittest.TestCase):
    def identity(self, **changes):
        values = dict(owner_id="TEST-SECURITY", owner_kind="security", scheme="security_code",
            value="123A0", valid_from=date(2020, 1, 1), valid_to=None,
            recorded_from=datetime(2024, 1, 1, tzinfo=timezone.utc), recorded_to=None,
            evidence_sha256="a" * 64, matching_method="synthetic_test")
        return IdentityVersion(**dict(values, **changes))

    def test_realistic_schema_and_incomplete_sample(self):
        row, profile = numad_sample(encoded(numad()) + b"\npartial")
        self.assertEqual(profile["row_count"], 1)
        self.assertFalse(profile["full_file_profiled"])
        for data in (encoded(numad()), b"{}\n", encoded(dict(numad(), sec_code=12345)) + b"\n"):
            with self.assertRaises(ContractError): numad_sample(data)

    def test_edinet_nulls_roles_and_duplicate_ids(self):
        rows, profile = edinet_metadata(metadata([filing(secCode=None)]))
        self.assertIsNone(rows[0]["secCode"])
        self.assertNotEqual(rows[0]["edinetCode"], rows[0]["issuerEdinetCode"])
        for data in (metadata([filing(), filing()]), b'[]',
                     metadata([filing(secCode=12345)]), metadata([filing(withdrawalStatus="9")])):
            with self.assertRaises(ContractError): edinet_metadata(data)

    def test_api_error_and_empty_day_are_not_validated_samples(self):
        with self.assertRaises(ContractError): edinet_metadata(b'{"metadata":{"status":"401"},"results":[]}')
        rows, profile = edinet_metadata(metadata([]))
        self.assertEqual(rows, [])
        self.assertIsNone(profile["schema_sha256"])

    def test_document_events_are_keyed_by_daily_sequence(self):
        rows, _ = edinet_metadata(metadata([filing(), filing(seqNumber=2, docInfoEditStatus="1")]))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["docID"], rows[1]["docID"])
        with self.assertRaises(ContractError):
            edinet_metadata(metadata([filing(seqNumber=True)]))

    def test_alpha_codes_validity_and_recording_intervals(self):
        self.assertEqual(self.identity().value, "123A0")
        self.assertEqual(self.identity(value="123A").value, "123A")
        item = self.identity(valid_to=date(2022, 1, 1))
        recorded = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.assertTrue(item.active(date(2021, 1, 1), recorded))
        self.assertFalse(item.active(date(2022, 1, 1), recorded))
        self.assertFalse(item.active(date(2021, 1, 1), datetime(2023, 1, 1, tzinfo=timezone.utc)))
        unknown = self.identity(valid_from=None, missing_reason="validity_unknown")
        self.assertFalse(unknown.active(date(2021, 1, 1), recorded))

    def test_ambiguous_mapping_and_invalid_owner_rejected(self):
        with self.assertRaises(ContractError): self.identity(owner_kind="entity")
        with self.assertRaises(ContractError): self.identity(value=12345)
        with self.assertRaises(ContractError): self.identity(valid_to=date(2019, 1, 1))
        with self.assertRaises(ContractError):
            resolve_identifier([self.identity(), self.identity(owner_id="SECOND")], "security_code", "123A0",
                               date(2021, 1, 1), datetime(2025, 1, 1, tzinfo=timezone.utc))

    def test_multiple_securities_renames_unlisted_entity(self):
        with tempfile.TemporaryDirectory() as temp:
            store = PrivateStore(Path(temp) / "private")
            entities = [Entity("TEST-ENTITY"), Entity("TEST-UNLISTED-FILER")]
            securities = [Security("TEST-SECURITY", "TEST-ENTITY", "ordinary"),
                          Security("TEST-SECOND", "TEST-ENTITY", "preferred")]
            old = self.identity(owner_id="TEST-ENTITY", owner_kind="entity", scheme="name", value="OLD",
                                valid_to=date(2022, 1, 1))
            new = replace(old, value="NEW", valid_from=date(2022, 1, 1), valid_to=None)
            path = save_master(store, entities, securities, [self.identity(), old, new])
            saved = json.loads((store.root / path).read_bytes())
            self.assertEqual(len(saved["securities"]), 2)
            self.assertEqual(len(saved["identifier_history"]), 3)
            with self.assertRaises(ContractError):
                save_master(store, entities, [Security("orphan", "missing", "ordinary")], [])


if __name__ == "__main__":
    unittest.main()
