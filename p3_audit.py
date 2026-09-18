"""P3 only: frozen P2 primary documents and metadata-discovered revision support."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json
from pathlib import Path
import re

from evidence_core import ContractError
from filing_catalog import edinet_metadata
from financial_facts import definitions, extract_candidates, canonicalize, reverse_verify, timestamp
from financial_views import reconcile, validate_lineage, fact_view
from local_edinet import LocalArchive
from metadata_gap_audit import ReadOnlyEvidence, snapshot_fingerprints
from p2_audit import canonical, CODE_FILES
from revision_series import inventory_series, revision_graph
from source_acquisition import PrivateStore, encoded, sha256, utcnow


def document_plan(selection, frame, limit=50):
    """Legacy parent-only frame helper; actual audits use metadata inventory_series."""
    primary = selection["challenge"] + selection["probability"]
    if len(primary) != len(set(primary)): raise ContractError("duplicate_sample_document")
    if not primary: raise ContractError("empty_p2_sample")
    selected, queue, missing = set(primary), list(primary), []
    while queue:
        doc = queue.pop()
        if doc not in frame: raise ContractError("sample_not_in_frozen_frame")
        parent = canonical(frame[doc]).get("parentDocID")
        if parent and parent not in selected:
            if parent not in frame: missing.append({"doc_id": doc, "parentDocID": parent, "reason": "revision_parent_missing"})
            else: selected.add(parent); queue.append(parent)
        if len(selected) > limit: raise ContractError("parent_closure_budget_exceeded")
    return {"primary": primary, "parent_support": sorted(selected - set(primary)), "all": sorted(selected),
            "missing_parents": missing, "selection_rule": "frozen_P2_plus_exact_parentDocID_closure_no_outcome_selection"}


def metadata_document(archive, record, recorded_at, sample_kind, cache):
    row = canonical(record)
    if not row: raise ContractError("metadata_missing")
    events, locators = [], []
    edited_times = []
    for event in record["metadata_events"]:
        listing, r = event["listing"], event["provider_fields"]
        relative = listing["relative_path"]
        if relative not in cache:
            artifact = archive.observe(relative)
            raw = archive.read(artifact)
            if sha256(raw) != listing["byte_sha256"]: raise ContractError("metadata_changed_since_p2")
            cache[relative] = (artifact, edinet_metadata(raw)[0])
        artifact, rows = cache[relative]
        if artifact["byte_sha256"] != listing["byte_sha256"]: raise ContractError("metadata_changed_since_p2")
        matches = [x for x in rows if x["docID"] == record["doc_id"] and x["seqNumber"] == r["seqNumber"]]
        if matches != [r]: raise ContractError("metadata_source_mismatch")
        locators.append({"source_artifact_sha256": artifact["byte_sha256"], "relative_path": relative,
                         "seqNumber": r["seqNumber"], "provider_fields": r, "day": listing["day"]})
        abnormal = r["withdrawalStatus"] != "0" or r["disclosureStatus"] != "0"
        edited = r["docInfoEditStatus"] != "0"
        at = timestamp(r.get("opeDateTime")) if abnormal or edited else timestamp(r.get("submitDateTime"))
        if edited: edited_times.append(at)
        events.append({"available_at": at, "blocked_reason": "withdrawn_or_disclosure_unavailable" if abnormal else None,
                       "withdrawalStatus": r["withdrawalStatus"], "docInfoEditStatus": r["docInfoEditStatus"],
                       "disclosureStatus": r["disclosureStatus"], "metadata_sha256": artifact["byte_sha256"]})
    submitted = timestamp(row.get("submitDateTime"))
    at = max([submitted, *edited_times]) if submitted and None not in edited_times else None
    variants = {k: {e["provider_fields"].get(k) for e in record["metadata_events"]}
                for k in ("parentDocID", "edinetCode", "docTypeCode", "submitDateTime")}
    conflicts = [reason for k, reason in (("parentDocID", "revision_parent_ambiguous"),
        ("edinetCode", "revision_entity_ambiguous"), ("docTypeCode", "revision_type_ambiguous"),
        ("submitDateTime", "revision_submit_time_ambiguous")) if len(variants[k]) != 1]
    # Do not let an arbitrarily chosen later timestamp hide a possibly earlier correction.
    if conflicts: at = None
    return {"doc_id": record["doc_id"], "edinet_code": row["edinetCode"], "secCode": row.get("secCode"),
        "parentDocID": row.get("parentDocID"), "doc_type": row.get("docTypeCode"), "sample_kind": sample_kind,
        "parentDocIDs": sorted(p for p in variants["parentDocID"] if p), "revision_conflicts": conflicts,
        "submit_datetime": row.get("submitDateTime"), "public_available_at": at,
        "availability_basis": "metadata_submit_or_edit_upper_bound_JST", "recorded_at": recorded_at,
        "status_events": events, "metadata_locators": locators, "document_failure": None,
        "provenance_class": archive.provenance_class, "synthetic": archive.provenance_class == "synthetic_fixture",
        "rights_review": "BLOCKED", "export_allowed": False}


def run(root, p2_snapshot, private_dir, snapshot, *, synthetic=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", snapshot): raise ContractError("invalid_snapshot_id")
    prior, source, output = Path(p2_snapshot).resolve(), Path(root).resolve(), (Path(private_dir) / snapshot).resolve()
    for path in (prior, source):
        LocalArchive._outside_git(path)
        if output == path or path in output.parents: raise ContractError("output_inside_input")
    before = snapshot_fingerprints(prior)
    selection = json.loads((prior / "selected_documents.json").read_bytes())
    manifest = json.loads((prior / "universe_manifest.json").read_bytes())
    frame = {}
    for r in map(json.loads, (prior / "universe_documents.jsonl").read_bytes().splitlines()):
        if r["doc_id"] in frame: raise ContractError("duplicate_frozen_doc_id")
        frame[r["doc_id"]] = r
    store = PrivateStore(output)
    if any(output.iterdir()): raise ContractError("snapshot_already_exists")
    archive = ReadOnlyEvidence(root, store, provenance_class="synthetic_fixture" if synthetic else "preexisting_local_official_archive")
    if archive.root_id != manifest["archive_root_id"]: raise ContractError("archive_root_mismatch")
    config = definitions()
    code = {n: sha256((Path(__file__).parent / n).read_text(encoding="utf-8").encode()) for n in
            (*CODE_FILES, "metadata_gap_audit.py", "financial_facts.py", "financial_views.py", "revision_series.py", "p3_audit.py", "registry/financial_definitions_v1.json")}
    common = {"snapshot_id": snapshot, "code_sha": sha256(encoded(code)), "p2_snapshot_id": manifest["snapshot_id"],
              "definition_version": config["definition_version"], "synthetic": synthetic, "export_allowed": False}
    def save(name, obj): store.publish(name, encoded(dict(common, **obj)) + b"\n")
    def lines(name, rows): store.publish(name, b"".join(encoded(dict(common, **r)) + b"\n" for r in rows))
    now = utcnow()
    inventory, plan, frame = inventory_series(archive, selection, frame, manifest)
    save("revision_inventory.json", inventory)
    save("audit_plan.json", dict(plan, created_at=now, code_files=code, p2_fingerprints=before))
    save("canonical_fact_definitions.json", {"definitions": config})
    documents, all_candidates, all_facts, failures, checks, coverage = [], [], [], [], [], []
    failures.extend(dict(f, stage="revision_inventory") for f in inventory["failures"])
    verified, cache = set(), {}
    p2_audits = {r["doc_id"]: r for r in map(json.loads, (prior / "document_audit.jsonl").read_bytes().splitlines())}
    for doc in plan["all"]:
        kind = "challenge" if doc in selection["challenge"] else "probability" if doc in selection["probability"] else "revision_support"
        d = {"doc_id": doc, "edinet_code": canonical(frame[doc]).get("edinetCode"), "parentDocID": canonical(frame[doc]).get("parentDocID"),
             "public_available_at": None, "recorded_at": now, "sample_kind": kind, "document_failure": None}
        facts, candidates = [], []
        try:
            d = metadata_document(archive, frame[doc], now, kind, cache)
            if d["revision_conflicts"]: raise ContractError("revision_metadata_ambiguous")
            if d["doc_type"] not in {"120", "130"}: raise ContractError("document_type_out_of_scope")
            paths = frame[doc]["zip_files"]
            if not paths: raise ContractError("revision_raw_missing" if kind == "revision_support" or d["doc_type"] == "130" else "raw_missing")
            if len(paths) != 1: raise ContractError("raw_missing_or_ambiguous")
            frozen = paths[0]
            if not (archive.root / frozen["relative_path"]).is_file():
                raise ContractError("revision_raw_missing" if kind == "revision_support" or d["doc_type"] == "130" else "raw_missing")
            artifact = archive.observe(frozen["relative_path"], doc_id=doc)
            if (artifact["source_mtime_ns"], artifact["byte_count"]) != (frozen["mtime_ns"], frozen["byte_count"]):
                raise ContractError("raw_changed_since_p2")
            if doc in p2_audits and artifact["byte_sha256"] != p2_audits[doc]["zip_sha256"]:
                raise ContractError("raw_hash_changed_since_p2")
            d["original_provider_retrieved_at"] = artifact["original_provider_retrieved_at"]
            d["artifact"] = artifact
            data = archive.read(artifact)
            candidates = extract_candidates(data, artifact, d, config)
            facts = canonicalize(candidates, config)
            checks.append(dict(doc_id=doc, **reverse_verify(data, artifact, d, config, facts)))
            verified.update(f["fact_id"] for f in facts)
        except ContractError as exc:
            d["document_failure"] = str(exc)
            failures.append({"doc_id": doc, "reason": str(exc), "stage": "document"})
        d["metadata_inventory_failure"] = inventory["status"] != "PASS"
        documents.append(d)
        all_candidates.extend(candidates); all_facts.extend(facts)
        for c in candidates:
            if c["missing_reason"]:
                failures.append({"doc_id": doc, "candidate_id": c["candidate_id"], "reason": c["missing_reason"], "stage": "mapping"})
        for family in config["families"]:
            fs = [f for f in facts if f["family"] == family]
            count = sum(f["normalized_value"] is not None for f in fs)
            coverage.append({"doc_id": doc, "sample_kind": kind, "family": family, "canonical_candidates": len(fs),
                "non_null": count, "normalized_value": None,
                "missing_reason": None if count else d["document_failure"] or ("no_accepted_mapping" if not fs else "all_candidates_blocked")})
    graph = revision_graph(documents)
    failures.extend(dict(f, stage="revision_graph") for f in graph["failures"])
    save("revision_series.json", graph)
    lineage_check = validate_lineage(all_facts, verified)
    reconciliation = reconcile(all_facts, documents)
    cutoff = datetime.fromisoformat(utcnow())
    views = fact_view(all_facts, documents, mode="latest_restated", snapshot_cutoff=cutoff,
                      allow_synthetic_for_tests=synthetic)
    transitions = []
    for d in documents:
        if not d.get("parentDocID") or not d.get("public_available_at"): continue
        at = datetime.fromisoformat(d["public_available_at"])
        for label, decision in (("at_exclusive_boundary", at), ("after_boundary", at + timedelta(microseconds=1))):
            if decision > cutoff: continue
            v = fact_view(all_facts, documents, mode="as_of", snapshot_cutoff=cutoff, decision_at=decision,
                          allow_synthetic_for_tests=synthetic)
            transitions.append({"revision_doc_id": d["doc_id"], "boundary": label, "decision_at": decision.isoformat(),
                "fact_ids": [f["fact_id"] for f in v["facts"]], "blocked": v["blocked"]})
    lines("documents.jsonl", documents)
    lines("xbrl_fact_candidates.jsonl", all_candidates)
    lines("canonical_facts.jsonl", all_facts)
    lines("reconciliation.jsonl", reconciliation)
    lines("lineage.jsonl", [{"fact_id": f["fact_id"], "input_ids": f["input_ids"], "candidate_id": f["candidate_id"],
        "source_artifact_sha256": f["source_artifact_sha256"], "xbrl_member_sha256": f["xbrl_member_sha256"],
        "element_index": f["element_index"], "definition_version": f["definition_version"],
        "verification_state": f["verification_state"]} for f in all_facts])
    lines("metric_coverage.jsonl", coverage)
    lines("failure_ledger.jsonl", failures)
    save("view_audit.json", {"latest_restated_fact_ids": [f["fact_id"] for f in views["facts"]], "blocked": views["blocked"],
                              "policy": views["revision_policy"]})
    lines("revision_as_of_audit.jsonl", transitions)
    proof = archive.prove_unchanged()
    after = snapshot_fingerprints(prior)
    if before != after: raise ContractError("p2_snapshot_changed")
    save("preservation_proof.json", {"p2_unchanged": True, "before": before, "after": after, "originals": proof})
    totals = defaultdict(Counter)
    for row in coverage:
        totals[row["sample_kind"]]["documents_with_" + row["family"]] += row["non_null"] > 0
    summary = {"primary_documents": len(plan["primary"]), "revision_support_documents": len(plan["revision_support"]),
        "revision_metadata_inventory": {k: v for k, v in inventory.items() if k not in {"listings", "failures"}},
        "revision_series_count": len(graph["components"]),
        "revision_series_blocked": sum(c["status"] == "BLOCKED" for c in graph["components"]),
        "revision_max_depth": max((c["max_depth"] or 0 for c in graph["components"]), default=0),
        "revision_as_of_boundaries_checked": len(transitions),
        "documents_audited": len(documents), "document_failures": sum(bool(d["document_failure"]) for d in documents),
        "numeric_candidates": len(all_candidates), "canonical_candidates": len(all_facts),
        "non_null_canonical_facts": sum(f["normalized_value"] is not None for f in all_facts),
        "source_reverse_checks": checks, "lineage": lineage_check, "coverage_by_sample": totals,
        "failure_counts": dict(Counter(f["reason"] for f in failures)),
        "reconciliation_counts": dict(Counter(c for r in reconciliation for c in r["classifications"])),
        "p2_selection_unchanged": True, "rights_review": "BLOCKED", "full_market_representativeness": "NOT ESTABLISHED",
        "live_api": "NOT RUN", "j_quants": "NOT RUN", "performance_research": "NOT RUN"}
    save("coverage_summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k != "source_reverse_checks"}))
    return summary


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("edinet-local-root", "p2-snapshot", "private-dir", "snapshot"): p.add_argument("--" + arg, required=True)
    a = p.parse_args()
    run(a.edinet_local_root, a.p2_snapshot, a.private_dir, a.snapshot)
