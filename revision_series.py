"""Local metadata closure and conservative revision graph validation; no acquisition."""
from collections import defaultdict
from datetime import date, datetime
import json

from evidence_core import ContractError
from filing_catalog import edinet_metadata
from source_acquisition import encoded, sha256

# EDINET API specification (2026-06), 4-1: document type codes outside annual reports.
NON_ANNUAL_TYPES = set("010 020 030 040 050 060 070 080 090 100 110 135 136 140 150 160 170 180 190 200 210 220 230 235 236 240 250 260 270 280 290 300 310 320 330 340 350 360 370 380".split())


def inventory_series(archive, selection, frozen_frame, frozen_manifest, limit=300):
    """Scan daily metadata, including IDs with no ZIP. Freeze closure before extraction."""
    primary = selection["challenge"] + selection["probability"]
    if not primary or len(primary) != len(set(primary)):
        raise ContractError("invalid_primary_selection")
    if any(d not in frozen_frame for d in primary): raise ContractError("sample_not_in_frozen_frame")
    nodes, locations, children = defaultdict(set), defaultdict(set), defaultdict(set)
    listings, failures = {}, []
    frozen = {x["relative_path"]: x for x in frozen_manifest.get("listings", [])}
    for path in sorted((archive.root / "listings").rglob("*.json")):
        relative = path.relative_to(archive.root).as_posix()
        if path.name.endswith(".manifest.json") or any(p.startswith(".") for p in path.relative_to(archive.root).parts): continue
        try:
            raw, st = archive._bytes(relative)
            rows, _ = edinet_metadata(raw)
            day = json.loads(raw)["metadata"]["parameter"]["date"]
            date.fromisoformat(day)
            entry = {"relative_path": relative, "day": day, "byte_sha256": sha256(raw),
                     "byte_count": len(raw), "mtime_ns": st.st_mtime_ns, "row_count": len(rows)}
            if relative in frozen and entry["byte_sha256"] != frozen[relative]["byte_sha256"]:
                raise ContractError("metadata_changed_since_p2")
            listings[relative] = entry
            for row in rows:
                doc, parent, kind = row["docID"], row.get("parentDocID"), row.get("docTypeCode")
                nodes[doc].add((parent, row.get("edinetCode"), kind))
                locations[doc].add(relative)
                if parent: children[parent].add(doc)
        except (ContractError, ValueError, KeyError, TypeError) as exc:
            reason = str(exc) if isinstance(exc, ContractError) else "metadata_schema_invalid"
            failures.append({"relative_path": relative, "reason": reason})
    for missing in sorted(frozen.keys() - listings.keys() - {x["relative_path"] for x in failures}):
        failures.append({"relative_path": missing, "reason": "metadata_file_missing"})
    if not listings: failures.append({"reason": "daily_metadata_not_available"})

    selected, queue, excluded = set(primary), list(primary), set()
    while queue:
        doc = queue.pop()
        neighbours = {v[0] for v in nodes.get(doc, ()) if v[0]}
        for child in children.get(doc, ()):
            types = {v[2] for v in nodes[child]}
            # 130 is an amended annual report. Confirmation (135), etc. is not a revision.
            # Missing/conflicting types are included so the auditor can block them explicitly.
            if len(types) != 1 or not types <= NON_ANNUAL_TYPES:
                neighbours.add(child)
            else: excluded.add((doc, child, tuple(sorted(types))))
        for linked in sorted(neighbours - selected): selected.add(linked); queue.append(linked)
        if len(selected) > limit: raise ContractError("revision_closure_budget_exceeded")

    records = {d: {"doc_id": d, "zip_files": [], "metadata_events": []} for d in selected}
    relevant_files = set().union(*(locations.get(d, set()) for d in selected))
    for relative in sorted(relevant_files):
        raw, _ = archive._bytes(relative)
        if sha256(raw) != listings[relative]["byte_sha256"]: raise ContractError("metadata_changed_during_closure")
        for row in edinet_metadata(raw)[0]:
            if row["docID"] in records:
                records[row["docID"]]["metadata_events"].append({"listing": listings[relative], "provider_fields": row})
    zip_index = archive.zip_index()
    for doc, record in records.items():
        record["metadata_events"].sort(key=lambda e: (e["listing"]["day"], e["provider_fields"]["seqNumber"]))
        if doc in frozen_frame:
            # Keep old size/mtime checks; never refresh a frozen ZIP signature after corruption.
            record["zip_files"] = list(frozen_frame[doc]["zip_files"])
            known = {p["relative_path"] for p in record["zip_files"]}
        else: known = set()
        for relative in zip_index.get(doc, []):
            if relative not in known:
                st = archive._path(relative).stat()
                record["zip_files"].append({"relative_path": relative, "byte_count": st.st_size, "mtime_ns": st.st_mtime_ns})
    days = sorted({x["day"] for x in listings.values()})
    manifest = {"status": "BLOCKED" if failures else "PASS", "failures": failures,
        "scope": "available_local_daily_metadata_only_not_current_official_completeness",
        "listing_count": len(listings), "metadata_doc_id_count": len(nodes),
        "date_range": [days[0], days[-1]] if days else None, "listings": list(listings.values())}
    manifest["inventory_sha256"] = sha256(encoded(manifest))
    plan = {"primary": primary, "revision_support": sorted(selected - set(primary)), "all": sorted(selected),
        "selection_rule": "frozen_P2_bidirectional_recursive_parentDocID_closure_annual_reports_v1",
        "limit": limit, "metadata_inventory_sha256": manifest["inventory_sha256"],
        "excluded_non_revision_relations": [{"parentDocID": p, "doc_id": d, "doc_types": list(t),
            "reason": "non_revision_document_type"} for p, d, t in sorted(excluded)]}
    return manifest, plan, records


def revision_graph(documents):
    """Invalid components are BLOCKED without crashing unrelated components."""
    docs = {d["doc_id"]: d for d in documents}
    if len(docs) != len(documents): raise ContractError("duplicate_document_id")
    adjacent, children, problems = defaultdict(set), defaultdict(set), defaultdict(set)
    for doc, d in docs.items():
        parents = set(d.get("parentDocIDs", [d.get("parentDocID")])) - {None, ""}
        for reason in d.get("revision_conflicts", []): problems[doc].add(reason)
        if d.get("metadata_inventory_failure"): problems[doc].add("revision_metadata_inventory_incomplete")
        if len(parents) > 1: problems[doc].add("revision_parent_ambiguous")
        if d.get("doc_type") == "130" and not parents: problems[doc].add("revision_parent_missing")
        for parent in parents:
            if parent not in docs: problems[doc].add("revision_parent_missing"); continue
            adjacent[doc].add(parent); adjacent[parent].add(doc); children[parent].add(doc)
            p = docs[parent]
            if not p.get("edinet_code") or not d.get("edinet_code"): problems[doc].add("revision_entity_unverified")
            elif p["edinet_code"] != d["edinet_code"]: problems[doc].add("revision_entity_mismatch")
            if p.get("public_available_at") and d.get("public_available_at") and (
                    datetime.fromisoformat(p["public_available_at"]) >= datetime.fromisoformat(d["public_available_at"])):
                problems[doc].add("revision_time_order_invalid")
    for parent, children_ids in children.items():
        if len(children_ids) > 1: problems[parent].add("ambiguous_revision_branches")
    roots, components, failures, seen = {}, [], [], set()
    for start in sorted(docs):
        if start in seen: continue
        component, queue = set(), [start]
        while queue:
            doc = queue.pop()
            if doc in component: continue
            component.add(doc); queue.extend(adjacent[doc] - component)
        seen.update(component)
        reasons = set().union(*(problems[d] for d in component))
        # Kahn's algorithm detects cycles even when the component also has a bad timestamp.
        indegree = {d: sum(d in children[p] for p in component) for d in component}
        ready = [d for d, n in indegree.items() if n == 0]; visited = 0
        depth = {d: 0 for d in ready}
        while ready:
            doc = ready.pop(); visited += 1
            for child in children[doc]:
                depth[child] = max(depth.get(child, 0), depth[doc] + 1)
                indegree[child] -= 1
                if indegree[child] == 0: ready.append(child)
        if visited != len(component): reasons.add("revision_cycle")
        origin = [d for d in component if not docs[d].get("parentDocID") and not docs[d].get("parentDocIDs")]
        if len(origin) != 1 and not reasons: reasons.add("revision_root_unresolved")
        root = origin[0] if len(origin) == 1 else None
        for doc in component: roots[doc] = root if not reasons else None
        item = {"series_id": min(component), "series_root": root, "doc_ids": sorted(component),
                "status": "BLOCKED" if reasons else "PASS", "reasons": sorted(reasons),
                "max_depth": max(depth.values(), default=0) if visited == len(component) else None}
        components.append(item)
        failures.extend({"series_id": item["series_id"], "doc_ids": item["doc_ids"], "reason": r} for r in sorted(reasons))
    return {"roots": roots, "components": components, "failures": failures}
