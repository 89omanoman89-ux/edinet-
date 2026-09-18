"""P4 only: immutable local J-Quants/P3 evidence audit and fail-closed PIT joins."""
import argparse
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
import json
from pathlib import Path
import re

from evidence_core import ContractError
from financial_facts import reverse_verify
from financial_views import fact_view
from jquants_local import JQuantsArchive, DATASETS
from local_edinet import LocalArchive
from metadata_gap_audit import ReadOnlyEvidence, snapshot_fingerprints
from pit_market import (DEFINITION, financial_observations, instant, join_fact,
                        price_observation, reconcile_sources)
from source_acquisition import PrivateStore, encoded, sha256, utcnow


def identity_candidates(documents, masters, calendar):
    """A daily code observation does NOT establish issuer identity or an open-ended interval."""
    output = []
    for d in documents:
        day = d.get("submit_datetime", "")[:10]
        matches = [r for r in masters if r["provider_fields"]["Code"] == d.get("secCode") and r["provider_fields"]["Date"] == day]
        evidence = [{"kind": "edinet_filing_metadata", "source_artifact_sha256": e["source_artifact_sha256"],
            "relative_path": e["relative_path"], "seqNumber": e["seqNumber"], "day": e["day"]} for e in d.get("metadata_locators", [])]
        reasons = ["identifier_validity_not_established", "issuer_security_relationship_unverified"]
        if not d.get("secCode"): reasons.insert(0, "edinet_security_code_null")
        elif len(matches) != 1: reasons.insert(0, "dated_security_master_missing_or_ambiguous")
        m = {"entity_id": "edinet:" + str(d.get("edinet_code")), "edinet_code": d.get("edinet_code"),
            "edinet_role": "filer", "issuer_entity_id": None, "subject_entity_id": None,
            "doc_id": d["doc_id"], "sample_kind": d.get("sample_kind"), "security_id": None,
            "jquants_code": d.get("secCode"), "observed_on": day,
            "identifier_validity_from": None, "identifier_validity_to": None, "identifier_validity_verified": False,
            "listing_from": None, "listing_to": None, "listing_verified": False,
            "public_available_at": d.get("public_available_at"), "matching_method": "exact_code_dated_candidate_only_no_name",
            "mapping_evidence": evidence, "jquants_master_observation_ids": [r["observation_id"] for r in matches],
            "status": "BLOCKED", "missing_reason": reasons[0], "missing_reasons": reasons,
            "synthetic": d.get("synthetic", False)}
        m["mapping_id"] = sha256(encoded(m)); output.append(m)
    return output


def run(jquants_root, edinet_root, p3_snapshot, private_dir, snapshot, *, synthetic=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", snapshot): raise ContractError("invalid_snapshot_id")
    prior, output = Path(p3_snapshot).resolve(), (Path(private_dir) / snapshot).resolve()
    for source in (prior, Path(jquants_root).resolve(), Path(edinet_root).resolve()):
        LocalArchive._outside_git(source)
        if source == output or source in output.parents: raise ContractError("output_inside_input")
    store = PrivateStore(output)
    if any(output.iterdir()): raise ContractError("snapshot_already_exists")
    before = snapshot_fingerprints(prior)
    def prior_obj(name): return json.loads((prior / name).read_bytes())
    def prior_lines(name): return list(map(json.loads, (prior / name).read_bytes().splitlines()))
    p3_plan = prior_obj("audit_plan.json"); config = prior_obj("canonical_fact_definitions.json")["definitions"]
    docs, facts = prior_lines("documents.jsonl"), prior_lines("canonical_facts.jsonl")
    if sorted(d["doc_id"] for d in docs) != sorted(p3_plan["all"]): raise ContractError("p3_document_plan_mismatch")
    if len(docs) > 100: raise ContractError("p4_document_budget_exceeded")
    if any(f["doc_id"] not in p3_plan["all"] for f in facts): raise ContractError("p3_orphan_fact")
    code_files = {n: sha256((Path(__file__).parent / n).read_text(encoding="utf-8").encode()) for n in
        ("p4_audit.py", "pit_market.py", "jquants_local.py", "financial_facts.py", "financial_views.py", "revision_series.py",
         "local_edinet.py", "metadata_gap_audit.py", "source_acquisition.py", "evidence_core.py", "registry/p4_contract_v1.json")}
    now = utcnow()
    common = {"snapshot_id": snapshot, "p3_snapshot_id": p3_plan["snapshot_id"], "code_sha": sha256(encoded(code_files)),
              "definition_version": DEFINITION, "synthetic": synthetic, "rights_review": "BLOCKED", "export_allowed": False}
    def save(name, value): store.publish(name, encoded(dict(common, **value)) + b"\n")
    def lines(name, values): store.publish(name, b"".join(encoded(dict(common, **x))+b"\n" for x in values))
    jq = JQuantsArchive(jquants_root, store, synthetic=synthetic)
    archive = ReadOnlyEvidence(edinet_root, store, provenance_class="synthetic_fixture" if synthetic else "preexisting_local_official_archive")
    days = sorted({d["submit_datetime"][:10] for d in docs if d.get("submit_datetime")})
    if not days: raise ContractError("sample_submission_dates_missing")
    windows = {dataset: [((date.fromisoformat(day)-timedelta(days=370 if dataset == "fins_summary" else 10)).isoformat(),
                          (date.fromisoformat(day)+timedelta(days=14)).isoformat()) for day in days]
               for dataset in DATASETS if dataset != "markets_calendar"}
    plan = jq.plan(windows)
    save("audit_plan.json", {"created_at": now, "p3_documents": p3_plan["all"], "primary": p3_plan["primary"],
        "revision_support": p3_plan["revision_support"], "selection_rule": "all_frozen_P3_documents_no_success_reselection",
        "code_files": code_files, "p3_fingerprints": before, "jquants_plan": plan,
        "decision_rule": "one_microsecond_after_each_document_public_available_upper_bound",
        "replay": "public_reconstruction_not_system_replay", "entry_rule": "first_available_daily_session_after_disclosure_and_decision"})
    save("definitions.json", {"contract": json.loads((Path(__file__).parent / "registry/p4_contract_v1.json").read_bytes())})
    codes = {d["secCode"] for d in docs if d.get("secCode")}
    profiles, observations, failures = [], [], []
    for f in plan["files"]:
        dataset = f["dataset"]
        def keep(r):
            if dataset == "markets_calendar": return True
            day = r["DiscDate" if dataset == "fins_summary" else "Date"]
            return r["Code"] in codes and any(lo <= day <= hi for lo, hi in windows[dataset])
        try:
            profile, rows = jq.inspect(f, keep)
            profiles.append(profile); observations.extend(rows)
        except ContractError as exc:
            profiles.append(dict(f, status="BLOCKED", missing_reason=str(exc)))
            failures.append({"stage": "jquants_inventory", "relative_path": f["relative_path"], "reason": str(exc)})
    save("jquants_inventory.json", {"plan": plan, "files": profiles, "original_files_audited": len(profiles),
        "status": "BLOCKED" if failures else "PASS", "source_version_vs_local_revision_separate": True,
        "unselected_files": "NOT RUN; declared ranges/counts are manifest claims only"})
    calendar = [r for r in observations if r["dataset"] == "markets_calendar"]
    masters = [r for r in observations if r["dataset"] == "equities_master"]
    prices, financial = [], []
    for row in observations:
        try:
            if row["dataset"] == "equities_bars_daily": prices.append(price_observation(row))
            if row["dataset"] == "fins_summary":
                extracted = financial_observations(row)
                financial.extend(extracted)
                if not extracted: failures.append({"stage": "financial_definition", "observation_id": row["observation_id"],
                    "reason": "jquants_financial_definition_or_time_out_of_scope"})
        except ContractError as exc: failures.append({"stage": "observation", "observation_id": row["observation_id"], "reason": str(exc)})
    mappings = identity_candidates(docs, masters, calendar)
    jq_reverse = jq.verify_rows(observations)
    by_doc = defaultdict(list)
    for fact in facts: by_doc[fact["doc_id"]].append(fact)
    verified, reverse = set(), []
    for doc in docs:
        if doc.get("document_failure"): continue
        try:
            a = doc["artifact"]
            proof = reverse_verify(archive.read(a), a, doc, config, by_doc[doc["doc_id"]])
            reverse.append(dict(doc_id=doc["doc_id"], **proof))
            verified.update(f["fact_id"] for f in by_doc[doc["doc_id"]])
        except ContractError as exc: failures.append({"stage": "edinet_reverse", "doc_id": doc["doc_id"], "reason": str(exc)})
    joined, reconciled, view_states, lineage = [], [], [], []
    cutoff = datetime.fromisoformat(now)
    inventory_failed = any(p.get("status") == "BLOCKED" for p in profiles)
    verified_observations = {r["observation_id"] for r in observations} if not inventory_failed else set()
    financial_index = defaultdict(list)
    for f in financial: financial_index[f["jquants_code"], f["period_end"] or f["instant_date"], f["metric"]].append(f)
    for doc in docs:
        if not doc.get("public_available_at"):
            failures.append({"stage": "p3_view", "doc_id": doc["doc_id"], "reason": "unknown_availability"}); continue
        decision = (instant(doc["public_available_at"]) + timedelta(microseconds=1)).isoformat()
        if instant(decision) > cutoff:
            failures.append({"stage": "p3_view", "doc_id": doc["doc_id"], "reason": "decision_after_snapshot"}); continue
        view = fact_view(facts, docs, mode="as_of", snapshot_cutoff=cutoff, decision_at=instant(decision), allow_synthetic_for_tests=synthetic)
        view_states.append({"trigger_doc_id": doc["doc_id"], "decision_at": decision,
                            "selected_fact_ids": [f["fact_id"] for f in view["facts"]], "blocked": view["blocked"]})
        for f in by_doc[doc["doc_id"]]:
            row = join_fact(f, view, [m for m in mappings if m["doc_id"] == doc["doc_id"]], calendar, prices, [],
                decision_at=decision, verified_fact_ids=verified,
                verified_observation_ids=verified_observations,
                requested_code=doc.get("secCode"), allow_synthetic_for_tests=synthetic)
            joined.append(row)
            lineage.append({"research_row_id": row["research_row_id"], "status": row["status"], "edinet_fact_id": f["fact_id"],
                "p3_canonical_artifact_sha256": before["canonical_facts.jsonl"]["byte_sha256"], "doc_id": f["doc_id"],
                "edinet_source": row["edinet_source"], "mapping_id": row["mapping_id"],
                "market_observation_id": row["market_observation_id"], "calendar_observation_ids": (row["trading_session"] or {}).get("calendar_observation_ids", []),
                "missing_reason": row["missing_reason"]})
            if row["status"] == "BLOCKED": failures.append({"stage": "pit_join", "research_row_id": row["research_row_id"], "reason": row["missing_reason"]})
            others = financial_index.get((doc.get("secCode"), f.get("period_end") or f.get("instant_date"), f["metric"]), [])
            if not others:
                reconciled.append({"edinet_fact_id": f["fact_id"], "jquants_fact_id": None, "classifications": ["unresolved"],
                    "missing_reason": "jquants_comparable_financial_overlap_unavailable", "decision_at": decision})
            for other in others:
                reconciled.append(dict(reconcile_sources(f, other, decision, identity_verified=row["mapping_id"] is not None,
                                                        edinet_is_revision=bool(doc.get("parentDocID")) or doc.get("doc_type") == "130"),
                                       edinet_pit_eligible=f in view["facts"]))
    for m in mappings:
        failures.extend({"stage": "identity", "mapping_id": m["mapping_id"], "doc_id": m["doc_id"], "reason": r} for r in m["missing_reasons"])
    failures.extend({"stage": "market_time", "observation_id": p["observation_id"], "reason": p["missing_reason"]} for p in prices if p.get("missing_reason"))
    lines("security_identity_map.jsonl", mappings); lines("trading_calendar.jsonl", calendar)
    lines("jquants_source_rows.jsonl", observations); lines("market_observations.jsonl", prices)
    lines("jquants_financial_observations.jsonl", financial); lines("pit_join_rows.jsonl", joined)
    lines("p3_view_states.jsonl", view_states); lines("cross_source_reconciliation.jsonl", reconciled)
    lines("lineage.jsonl", lineage); lines("failure_ledger.jsonl", failures)
    after = snapshot_fingerprints(prior)
    if before != after: raise ContractError("p3_snapshot_changed")
    save("preservation_proof.json", {"p3_unchanged": True, "before": before, "after": after,
        "jquants": jq.prove_unchanged(), "edinet": archive.prove_unchanged()})
    save("reverse_verification.json", {"jquants_rows": jq_reverse, "edinet": reverse})
    summary = {"documents": len(docs), "primary_documents": len(p3_plan["primary"]),
        "revision_support_documents": len(p3_plan["revision_support"]), "jquants_files_audited": len(profiles),
        "jquants_rows_retained": dict(Counter(r["dataset"] for r in observations)),
        "join_attempts": len(joined), "complete_pit_joins": sum(r["status"] == "PASS" for r in joined),
        "candidate_security_mappings": len(mappings), "verified_security_mappings": sum(m["status"] == "PASS" for m in mappings),
        "scheduled_entry_candidates": sum(r["entry_at"] is not None for r in joined),
        "edinet_source_checked_facts": sum(r["checked_facts"] for r in reverse),
        "source_reconciliation_counts": dict(Counter(c for r in reconciled for c in r["classifications"])),
        "failure_counts": dict(Counter(f["reason"] for f in failures)), "p3_unchanged": True,
        "p3_inherited_failure_counts": prior_obj("coverage_summary.json")["failure_counts"],
        "p3_failure_ledger_sha256": before["failure_ledger.jsonl"]["byte_sha256"],
        "empirical_pit_join": "PASS" if any(r["status"] == "PASS" for r in joined) else "BLOCKED",
        "new_acquisition": "NOT RUN", "system_replay": "NOT ESTABLISHED", "full_market_representativeness": "NOT ESTABLISHED",
        "performance_research": "NOT RUN", "p5": "NOT RUN"}
    save("coverage_summary.json", summary)
    print(json.dumps(summary))
    return summary


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("jquants-root", "edinet-local-root", "p3-snapshot", "private-dir", "snapshot"): p.add_argument("--"+name, required=True)
    a = p.parse_args()
    run(a.jquants_root, a.edinet_local_root, a.p3_snapshot, a.private_dir, a.snapshot)
