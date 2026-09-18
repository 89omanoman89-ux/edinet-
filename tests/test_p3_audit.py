"""Offline end-to-end P3 storage, freeze and failure tests; only synthetic bytes."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from evidence_core import ContractError
from financial_facts import reverse_verify
from metadata_gap_audit import snapshot_fingerprints
from p3_audit import run
from source_acquisition import encoded, sha256
from test_financial_facts import instance, archive
from test_metadata_gap_audit import daily, row


class P3AuditTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup)
        self.base = Path(t.name); self.root = self.base / "archive"; self.p2 = self.base / "p2"
        self.p2.mkdir(); (self.root / "documents").mkdir(parents=True)
        rows = [row(1, submitDateTime="2022-06-01 15:00"), row(2, edinetCode="E00001", docTypeCode="130", parentDocID="S0000001", submitDateTime="2022-06-01 15:01")]
        listing = self.root / "listings/2022-06-01/documents.json"; listing.parent.mkdir(parents=True)
        payload = json.loads(daily(rows)); payload["metadata"]["parameter"]["date"] = "2022-06-01"
        listing.write_bytes(encoded(payload))
        meta = {"relative_path": listing.relative_to(self.root).as_posix(), "day": "2022-06-01", "byte_sha256": sha256(listing.read_bytes())}
        frame, audits = [], []
        for r in rows:
            doc = r["docID"]; path = self.root / "documents" / (doc + ".zip")
            path.write_bytes(archive(instance()))
            frame.append({"doc_id": doc, "zip_files": [{"relative_path": path.relative_to(self.root).as_posix(),
                "byte_count": path.stat().st_size, "mtime_ns": path.stat().st_mtime_ns}],
                "metadata_events": [{"listing": meta, "provider_fields": r}]})
            audits.append({"doc_id": doc, "zip_sha256": sha256(path.read_bytes())})
        (self.p2 / "universe_manifest.json").write_bytes(encoded({"snapshot_id": "synthetic-p2", "archive_root_id": sha256(str(self.root.resolve()).encode())}))
        (self.p2 / "selected_documents.json").write_bytes(encoded({"challenge": ["S0000002"], "probability": []}))
        for name, items in (("universe_documents.jsonl", frame), ("document_audit.jsonl", audits)):
            (self.p2 / name).write_bytes(b"".join(encoded(x)+b"\n" for x in items))

    def audit(self):
        with redirect_stdout(io.StringIO()):
            return run(self.root, self.p2, self.base / "output", "synthetic-p3", synthetic=True)

    def test_complete_private_outputs_reverse_checks_and_no_input_mutation(self):
        before = {p: snapshot_fingerprints(p) for p in (self.root, self.p2)}
        result = self.audit()
        self.assertEqual(result["documents_audited"], 2)
        self.assertEqual(result["non_null_canonical_facts"], 2)
        self.assertEqual(result["lineage"]["status"], "PASS")
        self.assertEqual(before, {p: snapshot_fingerprints(p) for p in (self.root, self.p2)})
        out = self.base / "output/synthetic-p3"
        for name in ("canonical_fact_definitions.json", "xbrl_fact_candidates.jsonl", "canonical_facts.jsonl", "reconciliation.jsonl",
                     "lineage.jsonl", "coverage_summary.json", "failure_ledger.jsonl", "metric_coverage.jsonl"):
            self.assertTrue((out / name).exists())
        for line in (out / "canonical_facts.jsonl").read_bytes().splitlines():
            f = json.loads(line)
            self.assertTrue(f["synthetic"]); self.assertFalse(f["export_allowed"])
            self.assertEqual(f["snapshot_id"], "synthetic-p3")
            self.assertEqual(len(f["code_sha"]), 64)
        config=json.loads((out / "canonical_fact_definitions.json").read_bytes())["definitions"]
        documents={d["doc_id"]:d for d in map(json.loads,(out / "documents.jsonl").read_bytes().splitlines())}
        for f in map(json.loads,(out / "canonical_facts.jsonl").read_bytes().splitlines()):
            d=documents[f["doc_id"]]; a=d["artifact"]
            proof=reverse_verify((self.root/a["relative_path"]).read_bytes(),a,d,config,[f])
            self.assertEqual(proof["status"],"PASS")
        coverage = [json.loads(x) for x in (out / "metric_coverage.jsonl").read_bytes().splitlines()]
        self.assertTrue(any(x["missing_reason"] == "no_accepted_mapping" for x in coverage))

    def test_corrupt_original_recorded_and_never_restores_parent_value(self):
        (self.root / "documents/S0000002.zip").write_bytes(b'corrupt synthetic')
        result = self.audit()
        self.assertEqual(result["document_failures"], 1)
        out = self.base / "output/synthetic-p3"
        ledger = [json.loads(x) for x in (out / "failure_ledger.jsonl").read_bytes().splitlines()]
        self.assertIn("raw_changed_since_p2", {r["reason"] for r in ledger})
        view = json.loads((out / "view_audit.json").read_bytes())
        self.assertFalse(view["latest_restated_fact_ids"])

    def test_private_outputs_not_allowed_in_git_inputs_or_existing_snapshot(self):
        git = self.base / "git"; git.mkdir(); (git / ".git").mkdir()
        for target in (git, self.root, self.p2):
            with self.subTest(target=target), self.assertRaises(ContractError):
                run(self.root, self.p2, target, "forbidden", synthetic=True)
            self.assertFalse((target / "forbidden").exists())
        self.audit()
        with self.assertRaisesRegex(ContractError, "snapshot_already_exists"): self.audit()


if __name__ == "__main__": unittest.main()
