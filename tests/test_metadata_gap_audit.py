"""Synthetic metadata gaps only; no real document IDs, originals, keys or network."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from evidence_core import ContractError
from filing_catalog import EDINET_COLUMNS, edinet_metadata
import metadata_gap_audit as gaps
from source_acquisition import encoded, sha256
from test_p2_audit import xml, zipped


def row(n, **changes):
    item = dict.fromkeys(EDINET_COLUMNS)
    item.update(docID=f"S{n:07d}", seqNumber=n, edinetCode=f"E{n:05d}",
        submitDateTime="2022-01-31 15:00", docTypeCode="120", periodStart="2021-01-01", periodEnd="2021-12-31",
        withdrawalStatus="0", docInfoEditStatus="0", disclosureStatus="0")
    return dict(item, **changes)


def daily(rows):
    return encoded({"metadata": {"status": "200", "resultset": {"count": len(rows)},
        "parameter": {"date": "2022-01-31"}}, "results": rows})


class MetadataGapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source, self.prior = self.base / "source", self.base / "p2"
        self.prior.mkdir(); (self.source / "documents").mkdir(parents=True)
        self.rows = [row(1), row(2, docTypeCode="130", parentDocID="S0000001"),
                     row(9, docTypeCode="135", parentDocID="S00000a1", docInfoEditStatus="1")]
        self.listing = self.source / "listings/2022-01-31/documents.json"
        self.listing.parent.mkdir(parents=True)
        self.listing.write_bytes(daily(self.rows))
        self.records = []
        for n in range(1, 4):
            doc = f"S{n:07d}"
            path = self.source / "documents" / (doc + ".zip")
            path.write_bytes(zipped(xml(f"E{n:05d}")))
            self.records.append({"doc_id": doc, "zip_files": [{"relative_path": f"documents/{doc}.zip",
                "byte_count": path.stat().st_size, "mtime_ns": path.stat().st_mtime_ns}],
                "metadata_events": [] if n < 3 else [{"listing": {"day": "2021-01-31"},
                    "provider_fields": row(3, submitDateTime="2021-01-31 15:00")} ]})
        manifest = {"snapshot_id": "synthetic-p2", "available_doc_id_count": 3,
            "archive_root_id": sha256(str(self.source.resolve()).encode()),
            "inventory_failures": [{"relative_path": self.listing.relative_to(self.source).as_posix()}]}
        (self.prior / "universe_manifest.json").write_bytes(encoded(manifest))
        self.write_frame()
        for group in ("challenge", "probability"):
            (self.prior / f"{group}_sample.json").write_bytes(encoded({"doc_ids": ["S0000003"], "synthetic": True}))

    def write_frame(self):
        (self.prior / "universe_documents.jsonl").write_bytes(b"".join(encoded(r) + b"\n" for r in self.records))

    def audit(self):
        with redirect_stdout(io.StringIO()):
            return gaps.run(self.source, self.prior, self.base / "output", "synthetic-gap", expected_count=2, synthetic=True)

    def result_rows(self):
        path = self.base / "output/synthetic-gap/metadata_gap_records.jsonl"
        return [json.loads(line) for line in path.read_bytes().splitlines()]

    def test_mixed_case_parent_preserved_with_reference_warning(self):
        data = daily(self.rows)
        parsed, profile = edinet_metadata(data)
        self.assertEqual(parsed[2]["parentDocID"], "S00000a1")
        self.assertNotEqual(parsed[2]["parentDocID"], "S00000A1")
        self.assertEqual(profile["identifier_warnings"][0]["reason"], "parent_reference_case_unverified")
        self.assertEqual(len(parsed), 3)
        self.assertEqual(data, daily(self.rows))

    def test_normal_parent_and_null_have_no_warning(self):
        _, profile = edinet_metadata(daily(self.rows[:2]))
        self.assertEqual(profile["identifier_warnings"], [])

    def test_parent_relaxation_does_not_allow_paths_whitespace_unicode_or_wrong_lengths(self):
        for value in ("S000000", "S00000000", "S0000/01", "S0000 01", "Ｓ0000001", "s0000001", "", 123):
            with self.subTest(value=value), self.assertRaises(ContractError):
                edinet_metadata(daily([row(1, parentDocID=value)]))

    def test_bad_counts_and_other_identifiers_still_reject_entire_file(self):
        for data in (daily([row(1), row(2, docID="S00000a2")]),
            daily([row(1), row(2, edinetCode="UNKNOWN")]),
            daily([row(1), row(2, seqNumber=1)]),
            encoded({"metadata": {"status": "200", "resultset": {"count": 999}}, "results": self.rows})):
            with self.subTest(data=data), self.assertRaises(ContractError): edinet_metadata(data)

    def test_every_gap_resolved_and_historical_reason_retained(self):
        summary = self.audit()
        self.assertEqual(summary["metadata_linked_after"], 2)
        self.assertEqual(summary["unresolved_target_count"], 0)
        self.assertEqual(summary["parent_reference_warnings"], 1)
        self.assertEqual(summary["historical_reason_counts"], {"daily_file_rejected_by_parent_case_guard": 2})
        for r in self.result_rows():
            self.assertEqual(r["resolution"], "PASS")
            self.assertIsNone(r["missing_reason"])
            self.assertEqual(len(r["artifact"]["byte_sha256"]), 64)
            self.assertTrue(r["metadata_locators"])
            self.assertFalse(r["export_allowed"])

    def test_absent_target_is_unresolved_not_inferred(self):
        self.listing.write_bytes(daily(self.rows[1:]))
        self.assertEqual(self.audit()["unresolved_target_count"], 1)
        missing = self.result_rows()[0]
        self.assertEqual(missing["historical_missing_reason"], "unresolved")
        self.assertEqual(missing["missing_reason"], "unresolved")
        self.assertIsNone(missing["provider_fields"])

    def test_missing_daily_file_has_explicit_reason(self):
        self.listing.unlink()
        self.assertEqual(self.audit()["unresolved_reason_counts"], {"daily_metadata_not_available": 2})

    def test_raw_missing_and_corruption_do_not_promote_links(self):
        (self.source / "documents/S0000001.zip").unlink()
        (self.source / "documents/S0000002.zip").write_bytes(b"SYNTHETIC CHANGED")
        summary = self.audit()
        self.assertEqual(summary["unresolved_target_count"], 2)
        self.assertEqual(summary["unresolved_reason_counts"], {"raw_missing": 1, "byte_integrity_failed": 1})

    def test_ambiguous_metadata_is_not_chosen_arbitrarily(self):
        self.listing.write_bytes(daily(self.rows + [row(1, seqNumber=10, edinetCode="E99999")]))
        self.assertEqual(self.audit()["unresolved_reason_counts"], {"metadata_identity_ambiguous": 1})

    def test_dei_mismatch_blocks_metadata_link(self):
        self.rows[0]["edinetCode"] = "E99999"
        self.listing.write_bytes(daily(self.rows))
        self.assertEqual(self.audit()["unresolved_reason_counts"], {"original_metadata_identifier_mismatch": 1})

    def test_wrong_day_is_not_a_daily_tie(self):
        self.rows[0]["submitDateTime"] = "2022-02-01 15:00"
        self.listing.write_bytes(daily(self.rows))
        self.assertEqual(self.audit()["unresolved_reason_counts"], {"daily_date_submit_date_mismatch": 1})

    def test_bias_denominators_include_known_and_unknown_attributes(self):
        self.listing.write_bytes(daily(self.rows[1:]))
        self.audit()
        report = json.loads((self.base / "output/synthetic-gap/bias_summary.json").read_bytes())
        groups = report["groups"]
        self.assertEqual(sum(c["available_documents"] for c in groups["document_type"].values()), 3)
        self.assertEqual(groups["document_type"]["unknown"]["unresolved_after"], 1)
        self.assertEqual(groups["amendment"]["amended_annual_report"]["missing_before"], 1)

    def test_p2_and_original_bytes_names_and_mtimes_unchanged(self):
        before = {p: gaps.snapshot_fingerprints(p) for p in (self.prior, self.source)}
        self.audit()
        self.assertEqual(before, {p: gaps.snapshot_fingerprints(p) for p in (self.prior, self.source)})
        proof = json.loads((self.base / "output/synthetic-gap/preservation_proof.json").read_bytes())
        self.assertTrue(proof["p2_snapshot_unchanged"])
        self.assertEqual(proof["originals_read_only"]["status"], "PASS")

    def test_output_in_git_or_input_and_count_mismatch_are_rejected(self):
        git = self.base / "git"; git.mkdir(); (git / ".git").mkdir()
        for dest in (git, self.source, self.prior):
            with self.subTest(dest=dest), self.assertRaises(ContractError):
                gaps.run(self.source, self.prior, dest, "must-not-exist", expected_count=2)
            self.assertFalse((dest / "must-not-exist").exists())
        with self.assertRaisesRegex(ContractError, "frozen_gap_count_mismatch"):
            gaps.run(self.source, self.prior, self.base / "output", "bad-count", expected_count=1)

    def test_existing_output_never_overwritten(self):
        self.audit()
        with self.assertRaisesRegex(ContractError, "snapshot_already_exists"):
            self.audit()


if __name__ == "__main__": unittest.main()
