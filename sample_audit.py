"""Explicit opt-in network integration run; one numad row and one EDINET day only."""
import argparse
from datetime import date, datetime, timedelta
import os
from pathlib import Path

from evidence_core import ContractError, JST
from filing_catalog import edinet_metadata, numad_sample, save_filings
from original_tie import compare_zip, normalized
from local_edinet import LocalArchive, audit_local, select_sample
from source_acquisition import Acquirer, Fetch, PrivateStore, audit, gate, sha256

NUMAD_COMMIT = "e1dd7e00d5de82aa1b00cf7a28c829d327a93ca7"
NUMAD_ROOT = "https://huggingface.co/datasets/numad/yuho-text-2014-2022"
SAMPLE_YEAR = 2022
SAMPLE_LOCATOR = "jsonl:line:1"
API_SPEC_VERSION = "edinet-api-v2-2026-06"
TERMS = "https://disclosure2dl.edinet-fsa.go.jp/guide/static/disclosure/WZEK0030.html"
SPEC = "https://disclosure2dl.edinet-fsa.go.jp/guide/static/disclosure/download/ESE140206.pdf"
# Documentation actually inspected for this adapter. A changed document requires
# a new review; HTTP 200 alone must not promote docs_checked.
REVIEWED_CARD = "d4653a9f28f3c9c30c00b4ae2136596ebbbdb9fcb6457d01236e01b2b543fbe2"
REVIEWED_SPEC = "20b20e00739edf3a04d3dbd93ad55c06b1fb6fbb30375b5f06faae1e18c899b7"


def reviewed_docs(artifact, expected):
    return gate(None if artifact["byte_sha256"] == expected else "documentation_review_required",
                evidence_sha256=artifact["byte_sha256"], reviewed_sha256=expected)


def retention_check(submitted, checked_on):
    """Annual-report preflight, not a claim that a request returned 404.

    The reviewed specification permits 10 years with holiday extensions. A
    conservative 31-day boundary requires review instead of guessing expiry.
    Within the window, withdrawal/non-disclosure can still prevent retrieval.
    """
    submitted = date.fromisoformat(submitted)
    anniversary = submitted.replace(year=submitted.year + 10,
                                    day=min(submitted.day, 28) if submitted.month == 2 else submitted.day)
    reason = ("outside_official_retention_window" if checked_on > anniversary + timedelta(days=31)
              else "retention_boundary_requires_review" if checked_on >= anniversary else None)
    return gate(reason, submitted_on=submitted.isoformat(), evaluated_on=checked_on.isoformat(),
                basis="annual_report_spec_1-2-2_preflight_not_http_result",
                specification_url=SPEC, specification_sha256=REVIEWED_SPEC)


def tie_original(store, row, artifact):
    """Live-route guard; local artifacts never pass through this API wrapper."""
    if artifact.get("acquisition_method") == "preexisting_local_archive":
        return gate("local_archive_not_live_api")
    if artifact["status"] != "FETCHED":
        return gate(artifact["missing_reason"] or "original_not_fetched")
    expected = f"https://api.edinet-fsa.go.jp/api/v2/documents/{row['doc_id']}?type=1"
    if artifact["safe_url"] != expected or artifact["doc_id"] != row["doc_id"]:
        return gate("original_document_mismatch")
    return compare_zip(store.read_raw(artifact), row, artifact)


def run(private_dir, snapshot, edinet_day, secret_name=None, *, sample_year=SAMPLE_YEAR, stats=None,
        edinet_local_root=None):
    if sample_year not in (2014, 2022):
        raise ContractError("Only the fixed 2022 sample or 2014 historical negative case is supported")
    if edinet_local_root:
        source_root, output_root = Path(edinet_local_root).resolve(), Path(private_dir).resolve()
        if output_root == source_root or source_root in output_root.parents:
            raise ContractError("audit_store_must_not_modify_local_archive")
    store = PrivateStore(private_dir)
    if edinet_local_root and sample_year != 2022:
        raise ContractError("local_tie_requires_2022_sample")
    local_archive = LocalArchive(edinet_local_root, store) if edinet_local_root else None
    # The caller must explicitly name an approved environment secret; no .env search.
    client = Acquirer(store, secret_getter=os.environ.get if secret_name else None)
    card_url = f"{NUMAD_ROOT}/raw/{NUMAD_COMMIT}/README.md"
    card = client.fetch(Fetch("numad_docs", card_url, NUMAD_COMMIT, snapshot, card_url))
    terms = client.fetch(Fetch("edinet_terms", TERMS, "effective-2025-04-25", snapshot, TERMS))
    spec = client.fetch(Fetch("edinet_spec", SPEC, "v2-2026-06", snapshot, TERMS))
    sample = client.fetch(Fetch("numad", f"{NUMAD_ROOT}/resolve/{NUMAD_COMMIT}/yuho-{sample_year}.jsonl",
                               NUMAD_COMMIT, snapshot, card_url, range_end=65535, max_bytes=65536))
    sample_prefix, full_sample = sample, None
    docs = reviewed_docs(card, REVIEWED_CARD)
    # Dataset-card license assertion is not an upstream rights clearance.
    rights = gate("upstream_text_rights_unresolved", provider_license_claim="apache-2.0",
                  provider_evidence_sha256=card["byte_sha256"], upstream_terms_url=TERMS,
                  upstream_terms_sha256=terms["byte_sha256"], redistribution_permission=None)
    schema, tie = gate("sample_not_fetched"), gate("original_not_fetched")
    sample_row = None
    original = None
    selection, local_results = None, None
    retention = gate("sample_not_profiled")
    if sample["status"] == "FETCHED":
        try:
            sample_row, profile = numad_sample(store.read_raw(sample))
            if local_archive:
                index = local_archive.zip_index(sample_row["doc_id"])
                selected = select_sample(store.read_raw(sample), index)
                if selected is None:
                    full_sample = client.fetch(Fetch("numad", sample["safe_url"], NUMAD_COMMIT,
                        snapshot, card_url, max_bytes=256 * 1024 * 1024))
                    if full_sample["status"] != "FETCHED":
                        raise ContractError("numad_full_file_for_intersection_not_fetched")
                    selected = select_sample(store.read_raw(sample), index, store.read_raw(full_sample))
                    sample = full_sample
                sample_row, profile, selection = selected
                store.record("local_selections", dict(selection, provider_version=NUMAD_COMMIT,
                    artifact_sha256=sample["byte_sha256"], archive_root_id=local_archive.root_id))
                local_results = audit_local(local_archive, sample_row, index)
            schema = gate(**profile)
            store.record("sample_bindings", {"artifact_sha256": sample["byte_sha256"],
                "provider_version": NUMAD_COMMIT, "doc_id": sample_row["doc_id"],
                "file": f"yuho-{sample_year}.jsonl", "locator": profile["sample_locator"],
                "claimed_source_url": sample_row["url"],
                "verification": "unverified", "synthetic": False, "provenance_class": "third_party_derived"})
            retention = retention_check(sample_row["submit_date"], datetime.now(JST).date())
            if reviewed_docs(spec, REVIEWED_SPEC)["status"] != "PASS":
                retention = gate("retention_policy_review_required")
            if retention["status"] == "BLOCKED" or sample_year == 2014:
                tie = gate(retention["reason"] or "historical_archive_only", retention=retention)
                store.record("route_blocks", {"doc_id": sample_row["doc_id"], "snapshot": snapshot,
                                              "source_tied": tie, "http_attempted": False})
            else:
                original = client.fetch(Fetch("edinet_original",
                    f"https://api.edinet-fsa.go.jp/api/v2/documents/{sample_row['doc_id']}?type=1",
                    None, snapshot, TERMS, doc_id=sample_row["doc_id"],
                    secret_name=secret_name or "EDINET_API_KEY", interface_version=API_SPEC_VERSION))
                tie = tie_original(store, sample_row, original)
        except ContractError as exc:
            if local_archive and local_results is None:
                local_results = {key: gate(str(exc)) for key in ("local_official_original_located",
                    "local_official_original_byte_integrity", "local_official_original_tied",
                    "local_official_metadata_tied")}
            if sample_row is None:
                schema = gate("schema_mismatch")
            else:
                tie = gate("original_integrity_or_contract_failure")
    official = client.fetch(Fetch("edinet_official",
        f"https://api.edinet-fsa.go.jp/api/v2/documents.json?date={edinet_day}&type=2",
        None, snapshot, TERMS, secret_name=secret_name or "EDINET_API_KEY", interface_version=API_SPEC_VERSION))
    official_schema = gate("metadata_not_fetched")
    official_tie = gate("filing_original_not_tied_to_metadata")
    if official["status"] == "FETCHED":
        try:
            rows, profile = edinet_metadata(store.read_raw(official))
            official_schema = gate(profile.get("missing_reason"), **{k: v for k, v in profile.items()
                                                                    if k != "missing_reason"})
            save_filings(store, rows, official)
            if tie["status"] == "PASS" and any(r["docID"] == sample_row["doc_id"] for r in rows):
                official_tie = gate(doc_id=sample_row["doc_id"], metadata_sha256=official["byte_sha256"],
                                    original_sha256=original["byte_sha256"], comparison=tie)
        except ContractError:
            official_schema = gate("schema_mismatch")
    official_docs = reviewed_docs(spec, REVIEWED_SPEC)
    live_metadata = gate(official["missing_reason"] if official["status"] != "FETCHED"
                         else official_schema["reason"])
    live_original = gate(original["missing_reason"] if original and original["status"] != "FETCHED"
                         else tie["reason"] if not original or tie["reason"] == "original_parse_failed" else None)
    report = {"snapshot": snapshot, "synthetic": False, "scope": "one_numad_row_one_edinet_day",
        "sample": {"year": sample_year, "file": f"yuho-{sample_year}.jsonl",
                   "locator": f"jsonl:line:{selection['line_number']}" if selection else SAMPLE_LOCATOR,
                   "doc_id": sample_row["doc_id"] if sample_row else None, "retention": retention},
        "local_archive": local_results, "local_selection": selection,
        "routes": {"live_official_metadata_fetch": live_metadata, "live_official_original_fetch": live_original,
                   "live_official_original_tied": tie},
        "provenance": {"numad": "third_party_derived", "official_metadata": "live_official_api",
                       "official_original": "live_official_api", "local_archive": "preexisting_local_official_archive"},
        "artifacts": {"numad": sample, "official_metadata": official, "official_original": original},
        "sources": [audit("numad", docs=docs, artifact=sample, schema=schema, tie=tie, rights=rights),
            audit("edinet_official", docs=official_docs, artifact=official, schema=official_schema,
                  tie=official_tie,
                  rights=gate("reuse_scope_not_cleared", terms_url=TERMS,
                              terms_sha256=terms["byte_sha256"], redistribution_permission=None))]}
    path = store.record("audits", report)
    if stats is not None:
        stats.update(cache_hits=client.cache_hits, network_attempts=client.network_attempts,
                     fetched_artifacts=sum(a is not None and a["status"] == "FETCHED"
                                           for a in (card, terms, spec, sample_prefix, full_sample, original, official)),
                     sample_fetched=sample["status"] == "FETCHED")
    print("Private audit saved:", path)
    for source in report["sources"]:
        print(source["source_id"], {k: source[k]["status"] for k in
              ("docs_checked", "file_fetched", "schema_profiled", "source_tied", "rights_reviewed")})
    if local_results:
        print("local_archive", {k: v["status"] for k, v in local_results.items() if k != "artifact"})
    return report


def run_twice(private_dir, snapshot, edinet_day, secret_name=None, *, sample_year=SAMPLE_YEAR,
              edinet_local_root=None):
    """Verify actual cached bytes/manifests and counters; blocked routes stay blocked."""
    first_stats, second_stats = {}, {}
    run(private_dir, snapshot, edinet_day, secret_name, sample_year=sample_year, stats=first_stats,
        edinet_local_root=edinet_local_root)
    store = PrivateStore(private_dir)
    def inventory():
        return {p.relative_to(store.root).as_posix(): sha256(p.read_bytes())
                for kind in ("raw", "manifests", "completed", "local_manifests", "local_completed")
                for p in (store.root / kind).glob("*") if p.is_file()}
    before = inventory()
    second = run(private_dir, snapshot, edinet_day, secret_name, sample_year=sample_year, stats=second_stats,
                 edinet_local_root=edinet_local_root)
    after = inventory()
    checks = {"raw_manifest_checkpoint_unchanged": before == after,
              "no_duplicate_raw": {p for p in before if p.startswith("raw/")} ==
                                  {p for p in after if p.startswith("raw/")},
              "checkpoint_reused": second_stats["cache_hits"] == first_stats["fetched_artifacts"] > 0,
              "sample_fetched": first_stats["sample_fetched"] and second_stats["sample_fetched"],
              "second_network_attempts_zero": second_stats["network_attempts"] == 0}
    result = {"snapshot": snapshot, "status": "PASS" if all(checks.values()) else "BLOCKED",
              "checks": checks, "first": first_stats, "second": second_stats,
              "inventory_before": before, "inventory_after": after,
              "scope": "fetched_artifacts_only; blocked_routes_are_not_validated"}
    path = store.record("resume_checks", result)
    print("Private resume check:", result["status"], path)
    if result["status"] != "PASS":
        raise ContractError("Snapshot resume verification failed")
    return second, result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--edinet-date", required=True, type=date.fromisoformat)
    parser.add_argument("--edinet-secret-env", help="Explicitly approved secret setting name, never its value")
    parser.add_argument("--sample-year", type=int, choices=(2014, 2022), default=SAMPLE_YEAR)
    parser.add_argument("--verify-resume", action="store_true", help="Run twice and record cache/integrity checks")
    parser.add_argument("--edinet-local-root", help="Absolute read-only EDINET archive root outside Git")
    args = parser.parse_args()
    runner = run_twice if args.verify_resume else run
    runner(args.private_dir, args.snapshot, args.edinet_date, args.edinet_secret_env,
           sample_year=args.sample_year, edinet_local_root=args.edinet_local_root)
