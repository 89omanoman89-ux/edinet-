"""Explicit revision views, lossless reconciliation and checked derivation lineage."""
from collections import defaultdict
from datetime import date, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import combinations

from evidence_core import ContractError, aware
from source_acquisition import encoded, sha256

SEMANTICS = ("metric", "period_start", "period_end", "instant_date", "period_kind", "period_class",
             "consolidation", "accounting_standard", "normalized_unit", "share_basis")
ADDITIVE = {"revenue_sales", "revenue_ifrs", "operating_profit", "net_profit_total", "net_profit_owners", "cfo", "cfi"}


def semantic_key(f):
    # Keep dimensions including their namespace/placement; never merge segment totals.
    return encoded([*(f.get(k) for k in SEMANTICS), f.get("dimensions")])


def revision_roots(documents):
    docs = {d["doc_id"]: d for d in documents}
    if len(docs) != len(documents): raise ContractError("duplicate_document_id")
    roots = {}
    def visit(doc, stack):
        if doc in stack: raise ContractError("revision_cycle")
        if doc in roots: return roots[doc]
        d = docs[doc]; parent = d.get("parentDocID")
        if parent:
            if parent not in docs: roots[doc] = None; return None
            p = docs[parent]
            if p["edinet_code"] != d["edinet_code"]: raise ContractError("revision_entity_mismatch")
            if p.get("public_available_at") and d.get("public_available_at") and p["public_available_at"] >= d["public_available_at"]:
                raise ContractError("revision_time_order_invalid")
            roots[doc] = visit(parent, stack | {doc})
        else: roots[doc] = doc
        return roots[doc]
    for doc in docs: visit(doc, set())
    return roots


def reconcile(facts, documents):
    roots = revision_roots(documents)
    groups = defaultdict(list)
    for f in facts:
        groups[(f["edinet_code"], f["metric"], f.get("period_start"), f.get("period_end"), f.get("instant_date"))].append(f)
    output = []
    for rows in groups.values():
        for a, b in combinations(rows, 2):
            reasons = []
            for field, reason in (("consolidation", "scope_difference"), ("accounting_standard", "accounting_standard_difference"),
                                  ("normalized_unit", "unit_difference")):
                if a[field] is None or b[field] is None:
                    if "unresolved" not in reasons: reasons.append("unresolved")
                elif a[field] != b[field]: reasons.append(reason)
            if a["doc_id"] != b["doc_id"]:
                reasons.append("restatement_difference" if roots.get(a["doc_id"]) is not None and roots.get(a["doc_id"]) == roots.get(b["doc_id"]) else "unresolved")
            if semantic_key(a) != semantic_key(b) and not reasons: reasons.append("unresolved")
            if not reasons:
                if a["normalized_value"] is None or b["normalized_value"] is None: reasons.append("unresolved")
                else: reasons.append("exact_match" if Decimal(a["normalized_value"]) == Decimal(b["normalized_value"]) else "conflicting_facts")
            output.append({"candidate_fact_ids": [a["fact_id"], b["fact_id"]], "classifications": reasons,
                           "resolution": "candidates_preserved_no_aggregation"})
    return output


def fact_view(facts, documents, *, mode, snapshot_cutoff, decision_at=None, doc_id=None, replay="public_reconstruction", allow_synthetic_for_tests=False):
    """Latest only WITHIN explicit parent chains. Other filings remain separate series."""
    aware(snapshot_cutoff)
    if mode not in {"as_reported", "as_of", "latest_restated"}: raise ContractError("unknown_view")
    if replay not in {"public_reconstruction", "system_replay"}: raise ContractError("unknown_replay_mode")
    if mode == "as_of":
        aware(decision_at)
        if snapshot_cutoff < decision_at: raise ContractError("snapshot_before_decision")
    elif replay == "system_replay": raise ContractError("system_replay_requires_as_of")
    cutoff = decision_at if mode == "as_of" else snapshot_cutoff
    docs = {d["doc_id"]: d for d in documents}
    roots = revision_roots(documents)
    if any(f["doc_id"] not in docs for f in facts): raise ContractError("orphan_fact_document")
    visible, blocked = {}, []
    poisoned = set()
    for d in documents:
        if datetime.fromisoformat(d["recorded_at"]) > snapshot_cutoff: continue
        root = roots[d["doc_id"]]
        if root is None or not d.get("public_available_at"):
            blocked.append({"doc_id": d["doc_id"], "reason": "revision_parent_missing" if root is None else "unknown_availability"})
            poisoned.add(root); continue
        if datetime.fromisoformat(d["public_available_at"]) >= cutoff: continue
        if replay == "system_replay" and (not d.get("original_provider_retrieved_at") or
                datetime.fromisoformat(d["original_provider_retrieved_at"]) >= cutoff):
            blocked.append({"doc_id": d["doc_id"], "reason": "system_replay_acquisition_not_established"})
            poisoned.add(root); continue
        visible[d["doc_id"]] = d
    if mode == "as_reported":
        if doc_id is None: raise ContractError("as_reported_requires_doc_id")
        chosen = [doc_id] if doc_id in visible else []
    else:
        grouped = defaultdict(list)
        for d in visible.values(): grouped[roots[d["doc_id"]]].append(d)
        chosen = []
        for root, group in grouped.items():
            if root in poisoned: continue
            parent_ids = {d.get("parentDocID") for d in group}
            leaves = [d["doc_id"] for d in group if d["doc_id"] not in parent_ids]
            if len(leaves) != 1:
                blocked.append({"series_root": root, "reason": "ambiguous_revision_branches"}); continue
            chosen.extend(leaves)
    rows = []
    for winner in chosen:
        d = docs[winner]
        statuses = [e for e in d.get("status_events", []) if e.get("available_at") is not None and datetime.fromisoformat(e["available_at"]) < cutoff]
        unknown = any(e.get("available_at") is None for e in d.get("status_events", []))
        status = max(statuses, key=lambda e: e["available_at"]) if statuses else None
        reason = "unknown_status_time" if unknown else (status.get("blocked_reason") if status else None)
        if status and len({e.get("blocked_reason") for e in statuses if e["available_at"] == status["available_at"]}) > 1:
            reason = "ambiguous_status_events"
        if reason or d.get("document_failure"):
            blocked.append({"doc_id": winner, "reason": reason or d["document_failure"]}); continue
        selected = [f for f in facts if f["doc_id"] == winner]
        groups = defaultdict(list)
        for f in selected: groups[semantic_key(f)].append(f)
        for values in groups.values():
            if any(f.get("synthetic") for f in values) and not allow_synthetic_for_tests:
                blocked.append({"doc_id": winner, "reason": "synthetic_not_empirical"}); continue
            if any(not f.get("public_available_at") or datetime.fromisoformat(f["public_available_at"]) >= cutoff for f in values):
                blocked.append({"doc_id": winner, "reason": "fact_not_yet_available"}); continue
            if any(f["normalized_value"] is None for f in values):
                blocked.extend({"fact_id": f["fact_id"], "doc_id": winner, "reason": f["missing_reason"]} for f in values if f["normalized_value"] is None)
                continue
            if any(f["verification_state"] not in {"source_tied", "recomputed"} for f in values):
                blocked.append({"doc_id": winner, "reason": "unverified_facts"}); continue
            if any(f["representation"] not in {"reported", "derived"} for f in values):
                blocked.append({"doc_id": winner, "reason": "representation_not_allowed"}); continue
            if len({Decimal(f["normalized_value"]) for f in values}) > 1:
                blocked.append({"doc_id": winner, "reason": "conflicting_facts", "fact_ids": [f["fact_id"] for f in values]}); continue
            rows.extend(values)  # exact duplicate candidates remain individually traceable
        if mode != "as_reported":
            older = [f for f in facts if f["doc_id"] in visible and roots[f["doc_id"]] == roots[winner] and f["doc_id"] != winner]
            for key in {semantic_key(f) for f in older} - groups.keys():
                blocked.append({"doc_id": winner, "reason": "metric_absent_in_latest_revision", "semantic_key_sha256": sha256(key)})
    return {"mode": mode, "replay": replay, "facts": rows, "blocked": blocked,
            "revision_policy": "explicit_parent_chains_only_no_fallback", "snapshot_cutoff": snapshot_cutoff.isoformat(),
            "decision_at": decision_at.isoformat() if decision_at else None}


def derive_quarter(current, previous):
    comparable = ("edinet_code", "metric", "period_start", "fiscal_year_start", "consolidation",
                  "accounting_standard", "normalized_unit", "dimensions", "share_basis", "definition_version", "doc_id")
    if any(current.get(k) != previous.get(k) for k in comparable): raise ContractError("non_comparable_cumulative_facts")
    if current["metric"] not in ADDITIVE: raise ContractError("metric_not_additive")
    for f in (current, previous):
        if f["period_class"] != "cumulative" or f["period_kind"] != "duration" or not f.get("fiscal_year_start"):
            raise ContractError("cumulative_inputs_required")
        if f.get("period_start") != f["fiscal_year_start"]: raise ContractError("fiscal_year_mismatch")
    start = date.fromisoformat(previous["period_end"]) + timedelta(days=1)
    end = date.fromisoformat(current["period_end"])
    if not 70 <= (end - start).days + 1 <= 100: raise ContractError("non_quarter_difference")
    complete = all(f["normalized_value"] is not None and f["verification_state"] == "source_tied"
                   and f["representation"] == "reported" and f.get("public_available_at") for f in (current, previous))
    value = None
    if complete:
        values = [Decimal(f["normalized_value"]) for f in (current, previous)]
        with localcontext() as ctx:
            ctx.prec = max(len(v.as_tuple().digits) + abs(v.as_tuple().exponent) for v in values) + 4
            value = str(values[0] - values[1])
    out = dict(current, representation="derived", extraction_method="cumulative_difference_v1",
        definition_version="standalone_from_ytd.v1", input_ids=[current["fact_id"], previous["fact_id"]],
        original_qname=None, original_value=None, original_attributes=None, contextRef=None, unitRef=None,
        xbrl_member=None, xbrl_member_sha256=None, element_index=None, original_unit=None,
        context_xml=None, context_sha256=None, source_artifact_sha256=None,
        period_start=start.isoformat(), period_class="quarter", synthetic=current["synthetic"] or previous["synthetic"],
        public_available_at=max(current.get("public_available_at") or "", previous.get("public_available_at") or "") or None,
        normalized_value=value,
        missing_reason=None if complete else "incomplete_or_unverified_lineage",
        verification_state="recomputed" if complete else "unverified")
    out["fact_id"] = sha256(encoded([out["definition_version"], out["input_ids"]]))
    return out


def validate_lineage(facts, verified_source_ids):
    nodes = {f["fact_id"]: f for f in facts}
    if len(nodes) != len(facts): raise ContractError("duplicate_lineage_id")
    seen = set()
    def visit(identifier, stack):
        if identifier in stack: raise ContractError("lineage_cycle")
        if identifier not in nodes: raise ContractError("orphan_lineage")
        if identifier in seen: return
        f = nodes[identifier]
        if f["representation"] == "derived":
            for parent in f["input_ids"]: visit(parent, stack | {identifier})
            if f["definition_version"] != "standalone_from_ytd.v1" or len(f["input_ids"]) != 2:
                raise ContractError("unknown_derivation")
            expected = derive_quarter(*(nodes[p] for p in f["input_ids"]))
            if expected != f: raise ContractError("derived_lineage_mismatch")
        elif f["normalized_value"] is not None and (identifier not in verified_source_ids or f["verification_state"] != "source_tied"):
            raise ContractError("unverified_source_lineage")
        seen.add(identifier)
    for identifier in nodes: visit(identifier, set())
    return {"status": "PASS", "nodes": len(seen), "derived_nodes": sum(f["representation"] == "derived" for f in facts)}
