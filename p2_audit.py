"""P2 only: immutable local frames, separate challenge/probability samples, no live API."""
import argparse
from collections import Counter, defaultdict
from datetime import date
import json
from pathlib import Path
import re

from evidence_core import ContractError
from filing_catalog import edinet_metadata, numad_sample
from local_edinet import LocalArchive
from original_tie import compare_zip
from p2_schema import profile_zip
from sample_audit import NUMAD_COMMIT, NUMAD_ROOT
from source_acquisition import PrivateStore, encoded, gate, sha256, utcnow

CATEGORIES = ("jp_gaap", "ifrs", "consolidated", "non_consolidated", "amended_report",
    "parent_document", "unusual_status", "loss_fact", "fiscal_period_change_cue", "financial",
    "reit", "multiple_segments", "security_code_null", "alpha_security_code",
    "multiple_security_codes", "name_history", "large_zip", "multiple_xbrl_members",
    "same_tag_multiple_contexts", "third_party_overlap", "screening_failure")
CODE_FILES = ("p2_audit.py", "p2_schema.py", "local_edinet.py", "original_tie.py",
              "source_acquisition.py", "filing_catalog.py", "evidence_core.py", "sample_audit.py")
SELECTION_RULE = "sha256(seed + ':' + doc_id), doc_id; probability first over unique ZIP doc_ids"


def ranked(doc_ids, seed):
    return sorted(set(doc_ids), key=lambda doc: (sha256(f"{seed}:{doc}".encode()), doc))


def failure(reason):
    if "integrity" in reason or "changed" in reason: return "byte_integrity_failed"
    if "ambiguous" in reason or "document_id" in reason: return "identifier_ambiguous"
    if "not_available" in reason: return "raw_missing"
    if "size_limit" in reason: return "raw_size_limit"
    return "local_archive_contract_failed"


def inventory(archive):
    """The frame is locally available ZIP IDs, not all listed or all market filings."""
    index = archive.zip_index()
    records = {doc: {"doc_id": doc, "zip_files": [], "metadata_events": []} for doc in index}
    for doc, paths in index.items():
        for relative in paths:
            st = archive._path(relative).stat()
            records[doc]["zip_files"].append({"relative_path": relative, "byte_count": st.st_size,
                                             "mtime_ns": st.st_mtime_ns})
    listings, errors, listed_ids = [], [], set()
    for path in sorted((archive.root / "listings").rglob("*.json")):
        if path.name.endswith(".manifest.json"): continue
        relative = path.relative_to(archive.root).as_posix()
        try:
            data, st = archive._bytes(relative)
            payload = json.loads(data)
            day = payload["metadata"]["parameter"]["date"]
            date.fromisoformat(day)
            rows, _ = edinet_metadata(data)
            entry = {"relative_path": relative, "day": day, "byte_sha256": sha256(data),
                     "byte_count": len(data), "mtime_ns": st.st_mtime_ns, "row_count": len(rows)}
            listings.append(entry)
            for row in rows:
                listed_ids.add(row["docID"])
                if row["docID"] in records:
                    records[row["docID"]]["metadata_events"].append(
                        {"listing": entry, "provider_fields": row})
        except (ContractError, ValueError, KeyError, TypeError):
            errors.append({"relative_path": relative, "reason": "metadata_schema_invalid"})
    # Keep daily events intact. Only identical doc_id membership is deduplicated.
    for r in records.values():
        r["metadata_events"].sort(key=lambda e: (e["listing"]["day"], e["provider_fields"]["seqNumber"]))
    rows = [canonical(r) for r in records.values()]
    days = sorted({e["day"] for e in listings})
    submitted = sorted({r["submitDateTime"][:10] for r in rows if r.get("submitDateTime")})
    manifest = {"frame_definition": "unique_doc_ids_with_zip_in_explicit_local_archive",
        "available_doc_id_count": len(records), "available_date_range": [submitted[0], submitted[-1]] if submitted else None,
        "document_type_counts": dict(Counter(r.get("docTypeCode") or "unknown" for r in rows)),
        "edinet_code_count": len({r["edinetCode"] for r in rows if r.get("edinetCode")}),
        "security_code_coverage": {"present": sum(bool(r.get("secCode")) for r in rows),
                                   "null_or_metadata_missing": sum(not r.get("secCode") for r in rows)},
        "daily_metadata_coverage": {"files": len(listings), "unique_days": len(days),
            "date_range": [days[0], days[-1]] if days else None,
            "frame_docs_with_events": sum(bool(r["metadata_events"]) for r in records.values()),
            "listing_only_doc_ids": len(listed_ids - records.keys()), "invalid_files": len(errors)},
        "zip_availability": {"files": sum(map(len, index.values())), "doc_ids": len(index),
                             "duplicate_doc_ids": sum(len(v) > 1 for v in index.values())},
        "archive_snapshot_identifier": sha256(encoded({"records": records, "listings": listings, "errors": errors})),
        "archive_snapshot_basis": "ZIP paths/size/mtime and metadata bytes; selected ZIPs hashed during audit",
        "archive_root_id": archive.root_id, "listings": listings, "inventory_failures": errors,
        "full_market_representativeness": "NOT ESTABLISHED"}
    return manifest, records


def canonical(record):
    events = record["metadata_events"]
    submitted = [e for e in events if (e["provider_fields"].get("submitDateTime") or "")[:10] == e["listing"]["day"]]
    return (submitted or events or [{"provider_fields": {}}])[0]["provider_fields"]


def metadata_categories(records):
    history = defaultdict(lambda: {"names": set(), "codes": set()})
    for r in records.values():
        for event in r["metadata_events"]:
            row = event["provider_fields"]
            if row.get("edinetCode"):
                for key, field in (("names", "filerName"), ("codes", "secCode")):
                    if row.get(field): history[row["edinetCode"]][key].add(row[field])
    categories = {}
    for doc, record in records.items():
        row, hits = canonical(record), set()
        events = [e["provider_fields"] for e in record["metadata_events"]]
        if any(r.get("docTypeCode") == "130" for r in events): hits.add("amended_report")
        if any(r.get("parentDocID") for r in events): hits.add("parent_document")
        if any(r.get(k) not in (None, "0") for r in events for k in
               ("withdrawalStatus", "docInfoEditStatus", "disclosureStatus")): hits.add("unusual_status")
        if row and row.get("secCode") is None: hits.add("security_code_null")
        if re.search("[A-Z]", row.get("secCode") or ""): hits.add("alpha_security_code")
        h = history[row.get("edinetCode")]
        if len(h["codes"]) > 1: hits.add("multiple_security_codes")
        if len(h["names"]) > 1: hits.add("name_history")
        if any(f["byte_count"] >= 2 * 1024 * 1024 for f in record["zip_files"]): hits.add("large_zip")
        categories[doc] = hits
    return categories


def structural_categories(profile):
    hits, dei = set(), profile.get("dei", {})
    if "Japan GAAP" in dei.get("AccountingStandardsDEI", []): hits.add("jp_gaap")
    if "IFRS" in dei.get("AccountingStandardsDEI", []): hits.add("ifrs")
    consolidation = dei.get("WhetherConsolidatedFinancialStatementsArePreparedDEI", [])
    if "true" in consolidation: hits.add("consolidated")
    if "false" in consolidation or any("NonConsolidatedMember" in d[1] for d in profile.get("dimensions", [])):
        hits.add("non_consolidated")
    if profile.get("challenge_evidence", {}).get("loss_fact"): hits.add("loss_fact")
    starts, ends = dei.get("CurrentFiscalYearStartDateDEI", []), dei.get("CurrentFiscalYearEndDateDEI", [])
    if len(starts) == len(ends) == 1 and starts[0] and ends[0]:
        try:
            if not 363 <= (date.fromisoformat(ends[0]) - date.fromisoformat(starts[0])).days <= 366:
                hits.add("fiscal_period_change_cue")
        except ValueError: pass
    # Only explicit DEI industry strings count; no company-name guessing.
    industries = [v for k, values in dei.items() if k.startswith("IndustryCode") for v in values if v]
    if any(v in {"BNK", "INS", "SEC", "銀行業", "保険業", "証券業"} for v in industries): hits.add("financial")
    if any(v in {"REIT", "投資法人"} for v in industries): hits.add("reit")
    segment_members = {d[1] for d in profile.get("dimensions", []) if "Segment" in d[0] and "Member" in d[1]}
    if len(segment_members) >= 2: hits.add("multiple_segments")
    if profile.get("xbrl_member_count", 0) > 1: hits.add("multiple_xbrl_members")
    if profile.get("same_tag_multiple_contexts"): hits.add("same_tag_multiple_contexts")
    if profile.get("failures"): hits.add("screening_failure")
    return hits


def load_numad(manifest_path):
    if manifest_path is None: return {}, {"status": "BLOCKED", "reason": "third_party_overlap_not_available"}
    path = Path(manifest_path).resolve()
    LocalArchive._outside_git(path)
    m = json.loads(path.read_bytes())
    expected = f"{NUMAD_ROOT}/resolve/{NUMAD_COMMIT}/yuho-2022.jsonl"
    if m.get("provider_version") != NUMAD_COMMIT or m.get("safe_url") != expected:
        raise ContractError("third_party_fixed_version_required")
    data = PrivateStore(path.parent.parent).read_raw(m)
    rows, invalid, complete = {}, [], data.split(b"\n")[:-1]
    for number, line in enumerate(complete, 1):
        try:
            row, _ = numad_sample(line + b"\n")
            rows.setdefault(row["doc_id"], {"row": row, "line_number": number})
        except ContractError:
            invalid.append(number)
    return rows, {"status": "PASS", "manifest": m, "complete_lines": len(complete),
        "distinct_doc_ids": len(rows), "invalid_lines": invalid, "file": "yuho-2022.jsonl",
        "overlap_scope": "available_complete_prefix_rows_only; absence_is_not_dataset_wide_absence"}


def choose(records, categories, seed, probability_count=15, challenge_count=20, min_entities=30):
    order = ranked(records, seed)
    probability = order[:probability_count]
    available = [d for d in order if d not in probability]
    selected, reasons, category_status = [], {}, {}
    for category in CATEGORIES:
        candidates = [d for d in available if category in categories[d]]
        if category == "third_party_overlap":
            # Reserve three independently selected documents before observing tie results.
            chosen = [d for d in selected if d in candidates]
            for doc in candidates:
                if len(chosen) >= 3 or len(selected) >= challenge_count: break
                if doc not in selected:
                    selected.append(doc); chosen.append(doc)
            for doc in chosen: reasons.setdefault(doc, []).append(category)
            category_status[category] = gate(None if len(chosen) >= 3 else
                "insufficient_available_overlap_documents", doc_ids=chosen, target=3)
            continue
        existing = next((d for d in selected if d in candidates), None)
        doc = existing or next((d for d in candidates if d not in selected), None)
        if doc is not None and (doc in selected or len(selected) < challenge_count):
            if doc not in selected: selected.append(doc)
            reasons.setdefault(doc, []).append(category)
            category_status[category] = gate(doc_id=doc)
        else:
            category_status[category] = gate("challenge_budget_exhausted" if candidates else
                "not_found_in_available_archive_screen", searched_scope="metadata_frame_and_fixed_bounded_structural_screen")
    entities = {canonical(records[d]).get("edinetCode") for d in probability + selected} - {None}
    # Fill the declared budget, preferring new reporting entities, never audit successes.
    for doc in available:
        entity = canonical(records[doc]).get("edinetCode")
        if doc not in selected and entity and entity not in entities and len(selected) < challenge_count:
            selected.append(doc); entities.add(entity)
            reasons[doc] = ["reporting_entity_diversity"]
    for doc in available:
        if len(selected) >= challenge_count: break
        if doc not in selected:
            selected.append(doc); reasons[doc] = ["fixed_rank_fill"]
    shortages = []
    entities = {canonical(records[d]).get("edinetCode") for d in probability + selected} - {None}
    if len(probability) < probability_count or len(selected) < challenge_count:
        shortages.append("insufficient_documents")
    if len(entities) < min_entities: shortages.append("insufficient_reporting_entities")
    return {"probability": probability, "challenge": selected, "challenge_reasons": reasons,
        "challenge_categories": category_status, "failures": shortages,
        "status": "BLOCKED" if shortages else "PASS", "reporting_entity_count": len(entities),
        "separation": "disjoint; probability drawn first from entire available ZIP frame"}


def audit_document(archive, record, overlap):
    doc, row = record["doc_id"], canonical(record)
    out = {"doc_id": doc, "submit_date": (row.get("submitDateTime") or "")[:10] or None,
        "submit_datetime": row.get("submitDateTime"), "edinet_code": row.get("edinetCode"),
        "sec_code": row.get("secCode"), "roles": {r: row.get(k) for r, k in (
            ("filer", "edinetCode"), ("issuer", "issuerEdinetCode"), ("subject", "subjectEdinetCode"))},
        "parentDocID": row.get("parentDocID"), "document_type": row.get("docTypeCode"),
        "document_status": {k: row.get(k) for k in ("withdrawalStatus", "docInfoEditStatus", "disclosureStatus")},
        "metadata_events": record["metadata_events"], "source_provenance": archive.provenance_class,
        "failures": ["rights_unresolved"], "export_allowed": False,
        "local_original_integrity": gate("raw_missing"), "local_daily_metadata_tie": gate("metadata_missing"),
        "third_party_tie": gate("third_party_overlap_not_available"), "zip_sha256": None, "byte_count": None}
    if row.get("docTypeCode") not in {"120", "130"}: out["failures"].append("unknown_document_type")
    events = record["metadata_events"]
    if any(len({e["provider_fields"].get(k) for e in events if e["provider_fields"].get(k)}) > 1
           for k in ("edinetCode", "secCode", "submitDateTime")):
        out["failures"].append("identifier_ambiguous")
    matching = [e for e in events if e["listing"]["day"] == out["submit_date"]]
    if matching:
        try:
            item = matching[0]["listing"]
            data, st = archive._bytes(item["relative_path"])
            if sha256(data) != item["byte_sha256"] or st.st_mtime_ns != item["mtime_ns"]:
                raise ContractError("local_byte_integrity_failure")
            artifact = archive.observe(item["relative_path"])
            rows, _ = edinet_metadata(data)
            out["local_daily_metadata_tie"] = gate(None if any(r["docID"] == doc for r in rows) else
                "original_metadata_mismatch", artifact=artifact)
        except ContractError as exc:
            out["local_daily_metadata_tie"] = gate(failure(str(exc)))
    if out["local_daily_metadata_tie"]["reason"]: out["failures"].append(out["local_daily_metadata_tie"]["reason"])
    profile = {"parse_status": "BLOCKED", "failures": ["raw_missing"]}
    try:
        if not record["zip_files"]: raise ContractError("local_file_not_available")
        if len(record["zip_files"]) != 1: raise ContractError("ambiguous_local_document_versions")
        frozen = record["zip_files"][0]
        artifact = archive.observe(frozen["relative_path"], doc_id=doc)
        if artifact["byte_count"] != frozen["byte_count"] or artifact["source_mtime_ns"] != frozen["mtime_ns"]:
            raise ContractError("local_file_changed_since_inventory")
        data = archive.read(artifact)
        out.update(artifact=artifact, zip_sha256=artifact["byte_sha256"], byte_count=len(data),
                   local_original_integrity=gate(basis="observed_bytes_and_optional_local_log"))
        profile = profile_zip(data)
        out["failures"].extend(profile["failures"])
        codes = [v for v in profile.get("dei", {}).get("EDINETCodeDEI", []) if v]
        if len(codes) > 1: out["failures"].append("identifier_ambiguous")
        if codes and row.get("edinetCode") and codes != [row["edinetCode"]]:
            out["failures"].append("original_metadata_mismatch")
        if doc in overlap and profile["parse_status"] == "PASS" and not any(
            r in out["failures"] for r in ("identifier_ambiguous", "original_metadata_mismatch")):
            entry = overlap[doc]
            tied = compare_zip(data, entry["row"], artifact)
            reason = "third_party_mismatch" if tied["status"] != "PASS" else None
            out["third_party_tie"] = gate(reason, comparison=tied, numad_line=entry["line_number"],
                                          provider_version=NUMAD_COMMIT, file="yuho-2022.jsonl")
        elif doc in overlap:
            out["third_party_tie"] = gate("third_party_original_unverified")
    except ContractError as exc:
        reason = failure(str(exc))
        out["local_original_integrity"] = gate(reason)
        out["failures"].append(reason)
        if doc in overlap: out["third_party_tie"] = gate("third_party_original_unavailable")
    if out["third_party_tie"]["reason"]: out["failures"].append(out["third_party_tie"]["reason"])
    out["parse_status"] = profile["parse_status"]
    out["failures"] = sorted(set(out["failures"]))
    out["schema_summary"] = {k: profile.get(k) for k in ("xbrl_member_count", "qname_count", "qnames_sha256",
        "context_count", "unit_count", "schema_sha256")}
    return out, profile


def run(root, private_dir, snapshot, *, seed=20260918, probability_count=15, challenge_count=20,
        screen_limit=120, min_entities=30, numad_manifest=None, synthetic=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", snapshot): raise ContractError("invalid_snapshot_id")
    if min(probability_count, challenge_count, screen_limit, min_entities) < 1 or (
        probability_count + challenge_count + screen_limit > 300):
        raise ContractError("p2_budget_out_of_range")
    source, output = Path(root).resolve(), Path(private_dir).resolve()
    if output == source or source in output.parents: raise ContractError("output_inside_archive")
    store = PrivateStore(output / snapshot)
    if any(store.root.iterdir()): raise ContractError("snapshot_already_exists_no_reselection")
    archive = LocalArchive(root, store, provenance_class="synthetic_fixture" if synthetic else "preexisting_local_official_archive")
    hashes = {p: sha256((Path(__file__).parent / p).read_text(encoding="utf-8").encode("utf-8")) for p in CODE_FILES}
    common = {"snapshot_id": snapshot, "code_sha": sha256(encoded(hashes)), "code_sha_kind": "sha256_source_bundle",
              "synthetic": synthetic, "export_allowed": False}
    def save(name, value):
        store.publish(name, encoded(dict(common, **value)) + b"\n")
    def lines(name, values):
        store.publish(name, b"".join(encoded(dict(common, **v)) + b"\n" for v in values))
    manifest, records = inventory(archive)
    manifest.update(selection_timestamp=utcnow(), fixed_random_seed=seed, selection_rule=SELECTION_RULE,
        code_files=hashes, probability_count=probability_count, challenge_count=challenge_count,
        structural_screen_limit=screen_limit, minimum_reporting_entities=min_entities)
    # This durable frame is published BEFORE any sample selection or structural screening.
    save("universe_manifest.json", manifest)
    lines("universe_documents.jsonl", records.values())
    overlap, overlap_info = load_numad(numad_manifest)
    save("third_party_input.json", overlap_info)
    categories = metadata_categories(records)
    for doc in records.keys() & overlap.keys(): categories[doc].add("third_party_overlap")
    order = ranked(records, seed)
    # Bounded discovery is fixed from metadata, size and prefix availability; no tie result is used.
    screen = order[:probability_count]
    for category in CATEGORIES:
        screen += [d for d in order if category in categories[d]][:4]
    screen += order
    screen = list(dict.fromkeys(screen))[:screen_limit]
    save("screen_plan.json", {"doc_ids": screen, "rule": "probability prefix; four per metadata category; fixed rank fill"})
    screens = []
    for doc in screen:
        try:
            files = records[doc]["zip_files"]
            if len(files) != 1: raise ContractError("ambiguous_local_document_versions")
            data, st = archive._bytes(files[0]["relative_path"])
            if st.st_size != files[0]["byte_count"] or st.st_mtime_ns != files[0]["mtime_ns"]:
                raise ContractError("local_file_changed_since_inventory")
            p = profile_zip(data)
        except ContractError as exc:
            p = {"parse_status": "BLOCKED", "failures": [failure(str(exc))]}
        categories[doc].update(structural_categories(p))
        screens.append({"doc_id": doc, "categories": sorted(categories[doc]), "profile": p})
    lines("structural_screen.jsonl", screens)
    selected = choose(records, categories, seed, probability_count, challenge_count, min_entities)
    save("selected_documents.json", selected)
    for group in ("challenge", "probability"):
        save(f"{group}_sample.json", {"sample_kind": group, "doc_ids": selected[group],
            "fixed_random_seed": seed, "selection_rule": SELECTION_RULE,
            "reasons": {d: selected["challenge_reasons"][d] for d in selected[group]} if group == "challenge" else {},
            "status": selected["status"]})
    audits, profiles, ledger = [], [], []
    for group in ("challenge", "probability"):
        for doc in selected[group]:
            result, profile = audit_document(archive, records[doc], overlap)
            result["sample_kind"] = group
            audits.append(result)
            profiles.append(dict(profile, doc_id=doc, sample_kind=group))
            for reason in result["failures"]:
                ledger.append({"doc_id": doc, "sample_kind": group, "reason": reason,
                    "kind": "unavailable" if reason == "third_party_overlap_not_available" else "unresolved"})
    ledger += [{"doc_id": None, "sample_kind": "selection", "reason": r, "kind": "unresolved"}
               for r in selected["failures"]]
    ledger += [{"doc_id": None, "sample_kind": "inventory", "reason": r["reason"], "kind": "unresolved",
                "relative_path": r["relative_path"]} for r in manifest["inventory_failures"]]
    ledger += [{"doc_id": s["doc_id"], "sample_kind": "structural_screen", "reason": r, "kind": "unresolved"}
               for s in screens for r in s["profile"]["failures"]]
    lines("document_audit.jsonl", audits)
    lines("schema_profiles.jsonl", profiles)
    lines("failure_ledger.jsonl", ledger)
    coverage, ties = {}, {}
    for group in ("challenge", "probability"):
        items = [a for a in audits if a["sample_kind"] == group]
        coverage[group] = {"documents": len(items),
            "reporting_entities": len({a["edinet_code"] for a in items if a["edinet_code"]}),
            "explicit_issuer_role_codes": len({a["roles"]["issuer"] for a in items if a["roles"]["issuer"]}),
            "integrity_pass": sum(a["local_original_integrity"]["status"] == "PASS" for a in items),
            "metadata_tie_pass": sum(a["local_daily_metadata_tie"]["status"] == "PASS" for a in items),
            "xbrl_parse_pass": sum(a["parse_status"] == "PASS" for a in items),
            "failure_counts": dict(Counter(r for a in items for r in a["failures"]))}
        ties[group] = {"documents": len(items), "available_overlap": sum(a["doc_id"] in overlap for a in items),
            "source_tie_pass": sum(a["third_party_tie"]["status"] == "PASS" for a in items),
            "reasons": dict(Counter(a["third_party_tie"]["reason"] or "PASS" for a in items))}
    save("coverage_summary.json", {"samples": coverage, "unique_documents_audited": len(audits),
        "unique_reporting_entities": len({a["edinet_code"] for a in audits if a["edinet_code"]}),
        "structural_screen_documents": len(screen), "full_market_representativeness": "NOT ESTABLISHED",
        "rights_review": "BLOCKED", "live_api": "NOT RUN", "performance_research": "NOT RUN"})
    save("source_tie_summary.json", {"samples": ties,
        "interpretation": "agreement with derived text is not correctness of EDINET originals"})
    print(json.dumps({"snapshot": snapshot, "selection": selected["status"], "coverage": coverage, "ties": ties}))
    return {"manifest": manifest, "selected": selected, "coverage": coverage, "ties": ties}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edinet-local-root", required=True)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--seed", type=int, default=20260918)
    parser.add_argument("--probability-count", type=int, default=15)
    parser.add_argument("--challenge-count", type=int, default=20)
    parser.add_argument("--screen-limit", type=int, default=120)
    parser.add_argument("--min-entities", type=int, default=30)
    parser.add_argument("--numad-manifest")
    args = parser.parse_args()
    run(args.edinet_local_root, args.private_dir, args.snapshot, seed=args.seed,
        probability_count=args.probability_count, challenge_count=args.challenge_count,
        screen_limit=args.screen_limit, min_entities=args.min_entities, numad_manifest=args.numad_manifest)
