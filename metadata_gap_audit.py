"""Investigate frozen P2 metadata gaps only; no reselection, acquisition or P3 work."""
import argparse
from collections import Counter, defaultdict
from datetime import date
import json
from pathlib import Path
import re

from evidence_core import ContractError
from filing_catalog import edinet_metadata
from local_edinet import LocalArchive
from p2_audit import CODE_FILES, canonical, failure
from p2_schema import profile_zip
from source_acquisition import PrivateStore, encoded, gate, sha256, utcnow

SPEC = "https://disclosure2dl.edinet-fsa.go.jp/guide/static/disclosure/download/ESE140206.pdf"
SPEC_VERSION = "2026-06; 3-1-2-2 No.30, printed p.47; 4-1 printed p.87"


class ReadOnlyEvidence(LocalArchive):
    """Check every observed source file again before reporting completion."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observed = {}

    def _bytes(self, relative):
        data, stat = super()._bytes(relative)
        signature = {"byte_sha256": sha256(data), "byte_count": len(data), "mtime_ns": stat.st_mtime_ns}
        key = Path(relative).as_posix()
        if key in self.observed and self.observed[key] != signature:
            raise ContractError("source_changed_during_audit")
        self.observed[key] = signature
        return data, stat

    def prove_unchanged(self):
        before = dict(self.observed)
        for relative in before: self._bytes(relative)
        return {"status": "PASS", "files": before, "file_count": len(before)}


def snapshot_fingerprints(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file(): continue
        if root not in path.resolve().parents: raise ContractError("snapshot_path_escape")
        result[path.relative_to(root).as_posix()] = {
            "byte_sha256": sha256(path.read_bytes()), "byte_count": path.stat().st_size,
            "mtime_ns": path.stat().st_mtime_ns}
    return result


def diagnose_daily(archive, relative):
    result = {"relative_path": relative, "status": "BLOCKED", "reason": "unresolved",
              "reference_warnings": [], "original_rejection": None}
    try:
        artifact = archive.observe(relative)
        data = archive.read(artifact)
        result["artifact"] = artifact
        rows, profile = edinet_metadata(data)
        day = json.loads(data)["metadata"]["parameter"]["date"]
        date.fromisoformat(day)
        warnings = profile["identifier_warnings"]
        result.update(status="PASS", reason=None, day=day, row_count=len(rows),
                      schema_profile=profile, reference_warnings=warnings)
        if warnings:
            result["original_rejection"] = {"reason": "parent_doc_id_uppercase_only_guard",
                "legacy_pattern": "S[0-9A-Z]{7}", "field": "parentDocID",
                "rejected_sequences": [w["seqNumber"] for w in warnings],
                "effect": "entire_daily_file_rejected_in_p2", "reference_resolution": "unresolved",
                "specification_url": SPEC, "specification_version": SPEC_VERSION}
        return result, rows
    except ContractError as exc:
        reason = failure(str(exc))
        result["reason"] = "daily_metadata_not_available" if reason == "raw_missing" else (
            "daily_metadata_integrity_failed" if reason == "byte_integrity_failed" else "unresolved")
    except (ValueError, KeyError, TypeError):
        result["reason"] = "unresolved"
    return result, []


def investigate(archive, record, candidates, diagnostics):
    doc = record["doc_id"]
    result = {"doc_id": doc, "historical_missing_reason": "unresolved", "resolution": "BLOCKED",
        "missing_reason": "unresolved", "metadata_link": gate("unresolved"),
        "original_integrity": gate("raw_missing"), "provider_fields": None, "metadata_locators": [],
        "provenance_class": archive.provenance_class, "rights_review": "BLOCKED", "export_allowed": False}
    matches = candidates.get(doc, [])
    if matches:
        if any(e["diagnosis"].get("original_rejection") for e in matches):
            result["historical_missing_reason"] = "daily_file_rejected_by_parent_case_guard"
        # Do not select between conflicting dated identity or document-type claims.
        fields = ("edinetCode", "secCode", "submitDateTime", "docTypeCode", "periodStart", "periodEnd")
        signatures = {encoded({k: e["row"].get(k) for k in fields}) for e in matches}
        if len(signatures) > 1:
            result["missing_reason"] = "metadata_identity_ambiguous"
        else:
            row = matches[0]["row"]
            result["provider_fields"] = row
            same_day = [e for e in matches if (row.get("submitDateTime") or "")[:10] == e["diagnosis"]["day"]]
            result["missing_reason"] = None if same_day else "daily_date_submit_date_mismatch"
            result["metadata_locators"] = [{"relative_path": e["diagnosis"]["relative_path"],
                "byte_sha256": e["diagnosis"]["artifact"]["byte_sha256"], "seqNumber": e["row"]["seqNumber"],
                "day": e["diagnosis"]["day"]} for e in matches]
    elif diagnostics and all(d["reason"] == "daily_metadata_not_available" for d in diagnostics):
        result["missing_reason"] = "daily_metadata_not_available"
    try:
        files = record["zip_files"]
        if not files: raise ContractError("local_file_not_available")
        if len(files) != 1: raise ContractError("ambiguous_local_document_versions")
        frozen = files[0]
        artifact = archive.observe(frozen["relative_path"], doc_id=doc)
        if (artifact["byte_count"] != frozen["byte_count"] or artifact["source_mtime_ns"] != frozen["mtime_ns"]):
            raise ContractError("local_file_changed_since_p2")
        data = archive.read(artifact)
        result["artifact"] = artifact
        result["original_integrity"] = gate(byte_sha256=artifact["byte_sha256"], byte_count=len(data))
        profile = profile_zip(data)
        codes = [v for v in profile.get("dei", {}).get("EDINETCodeDEI", []) if v]
        result["original_identity_evidence"] = {"parse_status": profile["parse_status"], "edinet_codes": codes,
            "member_hashes": [{k: m[k] for k in ("member", "sha256")} for m in profile["members"]],
            "failures": profile["failures"]}
        if result["missing_reason"] is None:
            if profile["parse_status"] != "PASS": result["missing_reason"] = "original_xml_unverified"
            elif len(codes) != 1: result["missing_reason"] = "original_identifier_ambiguous_or_missing"
            elif codes[0] != result["provider_fields"].get("edinetCode"):
                result["missing_reason"] = "original_metadata_identifier_mismatch"
    except ContractError as exc:
        reason = failure(str(exc))
        result["original_integrity"] = gate(reason)
        result["missing_reason"] = reason
    result["metadata_link"] = gate(result["missing_reason"])
    result["resolution"] = "PASS" if result["missing_reason"] is None else "BLOCKED"
    return result


def bias_summary(records, results):
    """Descriptive counts within the frozen archive; unknown attributes stay unknown."""
    targets = {r["doc_id"]: r for r in results}
    groups = {k: defaultdict(lambda: {"available_documents": 0, "missing_before": 0, "unresolved_after": 0})
              for k in ("submission_year", "period_end_calendar_year", "document_type", "amendment", "has_parent", "submission_day")}
    for doc, record in records.items():
        target = targets.get(doc)
        row = (target["provider_fields"] or {}) if target else canonical(record)
        submitted, end, kind = row.get("submitDateTime"), row.get("periodEnd"), row.get("docTypeCode")
        values = {"submission_year": submitted[:4] if submitted else "unknown",
            "submission_day": submitted[:10] if submitted else "unknown",
            "period_end_calendar_year": end[:4] if end else "unknown", "document_type": kind or "unknown",
            "amendment": "amended_annual_report" if kind == "130" else "annual_report" if kind == "120" else "other_or_unknown",
            "has_parent": str(bool(row.get("parentDocID"))).lower() if row else "unknown"}
        for key, value in values.items():
            cell = groups[key][value]
            cell["available_documents"] += 1
            cell["missing_before"] += target is not None
            cell["unresolved_after"] += target is not None and target["resolution"] != "PASS"
    for values in groups.values():
        for cell in values.values():
            cell["missing_fraction_before"] = cell["missing_before"] / cell["available_documents"]
            cell["unresolved_fraction_after"] = cell["unresolved_after"] / cell["available_documents"]
    return {"groups": groups, "denominator": "frozen_p2_local_zip_frame",
        "attribute_basis": "P2 metadata plus newly linked target metadata; period-end year is not normalized fiscal year",
        "interpretation": "descriptive only; no full-market representativeness or causal assertion"}


def run(root, p2_snapshot, private_dir, snapshot, *, expected_count=102, synthetic=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", snapshot): raise ContractError("invalid_snapshot_id")
    source, prior, output = Path(root).resolve(), Path(p2_snapshot).resolve(), (Path(private_dir) / snapshot).resolve()
    for path in (source, prior):
        LocalArchive._outside_git(path)
        if output == path or path in output.parents: raise ContractError("output_inside_input")
    if not 1 <= expected_count <= 300: raise ContractError("metadata_gap_budget_out_of_range")
    before = snapshot_fingerprints(prior)
    manifest = json.loads((prior / "universe_manifest.json").read_bytes())
    records = {}
    for row in map(json.loads, (prior / "universe_documents.jsonl").read_bytes().splitlines()):
        if row["doc_id"] in records: raise ContractError("duplicate_frozen_doc_id")
        records[row["doc_id"]] = row
    targets = {d: r for d, r in records.items() if not r["metadata_events"]}
    if len(targets) != expected_count or len(records) != manifest["available_doc_id_count"]:
        raise ContractError("frozen_gap_count_mismatch")
    store = PrivateStore(output)
    if any(output.iterdir()): raise ContractError("snapshot_already_exists")
    archive = ReadOnlyEvidence(root, store, provenance_class="synthetic_fixture" if synthetic else "preexisting_local_official_archive")
    if archive.root_id != manifest["archive_root_id"]: raise ContractError("archive_root_does_not_match_p2")
    hashes = {name: sha256((Path(__file__).parent / name).read_text(encoding="utf-8").encode())
              for name in ("metadata_gap_audit.py", *CODE_FILES)}
    common = {"snapshot_id": snapshot, "code_sha": sha256(encoded(hashes)), "synthetic": synthetic,
              "p2_snapshot_id": manifest["snapshot_id"], "export_allowed": False}
    def save(name, data): store.publish(name, encoded(dict(common, **data)) + b"\n")
    def save_lines(name, rows):
        store.publish(name, b"".join(encoded(dict(common, **r)) + b"\n" for r in rows))
    save("audit_plan.json", {"created_at": utcnow(), "code_files": hashes, "target_doc_ids": sorted(targets),
        "scope": "all_frozen_p2_metadata_gaps_and_previously_rejected_daily_files",
        "p2_fingerprints_before": before, "specification_url": SPEC, "specification_version": SPEC_VERSION})
    diagnostics, candidates = [], defaultdict(list)
    for entry in manifest["inventory_failures"]:
        diagnosis, rows = diagnose_daily(archive, entry["relative_path"])
        diagnostics.append(diagnosis)
        for row in rows:
            if row["docID"] in targets:
                candidates[row["docID"]].append({"row": row, "diagnosis": diagnosis})
    save_lines("daily_file_diagnostics.jsonl", diagnostics)
    results = [investigate(archive, targets[d], candidates, diagnostics) for d in sorted(targets)]
    save_lines("metadata_gap_records.jsonl", results)
    save("bias_summary.json", bias_summary(records, results))
    source_proof = archive.prove_unchanged()
    after = snapshot_fingerprints(prior)
    if before != after: raise ContractError("p2_snapshot_changed")
    save("preservation_proof.json", {"p2_snapshot_unchanged": True, "p2_before": before, "p2_after": after,
                                     "originals_read_only": source_proof})
    counts = dict(Counter(r["historical_missing_reason"] for r in results))
    unresolved = [r for r in results if r["resolution"] != "PASS"]
    summary = {"target_count": len(results), "all_have_reason": all(r["historical_missing_reason"] for r in results),
        "historical_reason_counts": counts, "metadata_linked_after": len(results) - len(unresolved),
        "unresolved_target_count": len(unresolved),
        "unresolved_reason_counts": dict(Counter(r["missing_reason"] for r in unresolved)),
        "rejected_daily_files": len(diagnostics), "daily_files_parsed_after": sum(d["status"] == "PASS" for d in diagnostics),
        "parent_reference_warnings": sum(len(d["reference_warnings"]) for d in diagnostics),
        "p2_samples_unchanged": True, "raw_read_only": True, "rights_review": "BLOCKED",
        "p3": "NOT RUN", "live_api": "NOT RUN", "j_quants": "NOT RUN", "performance_research": "NOT RUN"}
    save("summary.json", summary)
    print(json.dumps(summary))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edinet-local-root", required=True)
    parser.add_argument("--p2-snapshot", required=True)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--expected-missing-count", type=int, default=102)
    args = parser.parse_args()
    run(args.edinet_local_root, args.p2_snapshot, args.private_dir, args.snapshot, expected_count=args.expected_missing_count)
