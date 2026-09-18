"""Explicit opt-in network integration run; one numad row and one EDINET day only."""
import argparse
from datetime import date
from html.parser import HTMLParser
import io
import os
import re
import zipfile
from xml.etree import ElementTree

from evidence_core import ContractError
from filing_catalog import edinet_metadata, numad_sample, save_filings
from source_acquisition import Acquirer, Fetch, PrivateStore, audit, gate

NUMAD_COMMIT = "e1dd7e00d5de82aa1b00cf7a28c829d327a93ca7"
NUMAD_ROOT = "https://huggingface.co/datasets/numad/yuho-text-2014-2022"
TERMS = "https://disclosure2dl.edinet-fsa.go.jp/guide/static/disclosure/WZEK0030.html"
SPEC = "https://disclosure2dl.edinet-fsa.go.jp/guide/static/disclosure/download/ESE140206.pdf"
# Documentation actually inspected for this adapter. A changed document requires
# a new review; HTTP 200 alone must not promote docs_checked.
REVIEWED_CARD = "d4653a9f28f3c9c30c00b4ae2136596ebbbdb9fcb6457d01236e01b2b543fbe2"
REVIEWED_SPEC = "20b20e00739edf3a04d3dbd93ad55c06b1fb6fbb30375b5f06faae1e18c899b7"


def reviewed_docs(artifact, expected):
    return gate(None if artifact["byte_sha256"] == expected else "documentation_review_required",
                evidence_sha256=artifact["byte_sha256"], reviewed_sha256=expected)


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def normalized(text):
    parser = Text()
    parser.feed(text)
    return re.sub(r"\s+", "", " ".join(parser.parts))


def tie_original(store, row, artifact):
    """Exact tag/text tie to bytes fetched at the official document API.

    This is a deterministic text comparison, not an authenticity attestation or
    an independent measurement. Never accepts a doc ID or URL alone as proof.
    """
    if artifact["status"] != "FETCHED":
        return gate(artifact["missing_reason"] or "original_not_fetched")
    expected = f"https://api.edinet-fsa.go.jp/api/v2/documents/{row['doc_id']}?type=1"
    if artifact["safe_url"] != expected or artifact["doc_id"] != row["doc_id"]:
        return gate("original_document_mismatch")
    data = store.read_raw(artifact)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(i.file_size for i in archive.infolist()) > 32 * 1024 * 1024:
                return gate("original_expansion_limit")
            matches = []
            for info in archive.infolist():
                if not info.filename.lower().endswith(".xbrl"):
                    continue
                xml = archive.read(info)
                if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
                    return gate("xml_entities_rejected")
                for element in ElementTree.fromstring(xml).iter():
                    if element.tag.rsplit("}", 1)[-1] == row["tag"]:
                        if normalized("".join(element.itertext())) == normalized(row["text"]):
                            matches.append({"member": info.filename, "tag": element.tag,
                                            "context_ref": element.get("contextRef")})
            if not matches:
                return gate("original_tag_text_not_matched")
            return gate(original_sha256=artifact["byte_sha256"], doc_id=row["doc_id"],
                        locators=matches, method="xbrl_tag_normalized_text_exact_v1",
                        original_retrieved_at=artifact["retrieved_at"])
    except (zipfile.BadZipFile, ElementTree.ParseError, RuntimeError, ValueError):
        return gate("original_parse_failed")


def run(private_dir, snapshot, edinet_day, secret_name=None):
    store = PrivateStore(private_dir)
    # The caller must explicitly name an approved environment secret; no .env search.
    client = Acquirer(store, secret_getter=os.environ.get if secret_name else None)
    card_url = f"{NUMAD_ROOT}/raw/{NUMAD_COMMIT}/README.md"
    card = client.fetch(Fetch("numad_docs", card_url, NUMAD_COMMIT, snapshot, card_url))
    terms = client.fetch(Fetch("edinet_terms", TERMS, "effective-2025-04-25", snapshot, TERMS))
    spec = client.fetch(Fetch("edinet_spec", SPEC, "v2-2026-06", snapshot, TERMS))
    sample = client.fetch(Fetch("numad", f"{NUMAD_ROOT}/resolve/{NUMAD_COMMIT}/yuho-2014.jsonl",
                               NUMAD_COMMIT, snapshot, card_url, range_end=65535, max_bytes=65536))
    docs = reviewed_docs(card, REVIEWED_CARD)
    # Dataset-card license assertion is not an upstream rights clearance.
    rights = gate("upstream_text_rights_unresolved", provider_license_claim="apache-2.0",
                  provider_evidence_sha256=card["byte_sha256"], upstream_terms_url=TERMS,
                  upstream_terms_sha256=terms["byte_sha256"], redistribution_permission=None)
    schema, tie = gate("sample_not_fetched"), gate("original_not_fetched")
    sample_row = None
    if sample["status"] == "FETCHED":
        try:
            sample_row, profile = numad_sample(store.read_raw(sample))
            schema = gate(**profile)
            store.record("sample_bindings", {"artifact_sha256": sample["byte_sha256"],
                "provider_version": NUMAD_COMMIT, "doc_id": sample_row["doc_id"],
                "locator": "jsonl:line:1", "claimed_source_url": sample_row["url"],
                "verification": "unverified", "synthetic": False})
            original = client.fetch(Fetch("edinet_original",
                f"https://api.edinet-fsa.go.jp/api/v2/documents/{sample_row['doc_id']}?type=1",
                None, snapshot, TERMS, doc_id=sample_row["doc_id"],
                secret_name=secret_name or "EDINET_API_KEY", interface_version="edinet-api-v2"))
            tie = tie_original(store, sample_row, original)
        except ContractError:
            if sample_row is None:
                schema = gate("schema_mismatch")
            else:
                tie = gate("original_integrity_or_contract_failure")
    official = client.fetch(Fetch("edinet_official",
        f"https://api.edinet-fsa.go.jp/api/v2/documents.json?date={edinet_day}&type=2",
        None, snapshot, TERMS, secret_name=secret_name or "EDINET_API_KEY", interface_version="edinet-api-v2"))
    official_schema = gate("metadata_not_fetched")
    if official["status"] == "FETCHED":
        try:
            rows, profile = edinet_metadata(store.read_raw(official))
            official_schema = gate(profile.get("missing_reason"), **{k: v for k, v in profile.items()
                                                                    if k != "missing_reason"})
            save_filings(store, rows, official)
        except ContractError:
            official_schema = gate("schema_mismatch")
    official_docs = reviewed_docs(spec, REVIEWED_SPEC)
    report = {"snapshot": snapshot, "synthetic": False, "scope": "one_numad_row_one_edinet_day",
        "sources": [audit("numad", docs=docs, artifact=sample, schema=schema, tie=tie, rights=rights),
            audit("edinet_official", docs=official_docs, artifact=official, schema=official_schema,
                  tie=gate("filing_original_not_tied_to_metadata"),
                  rights=gate("reuse_scope_not_cleared", terms_url=TERMS,
                              terms_sha256=terms["byte_sha256"], redistribution_permission=None))]}
    path = store.record("audits", report)
    print("Private audit saved:", path)
    for source in report["sources"]:
        print(source["source_id"], {k: source[k]["status"] for k in
              ("docs_checked", "file_fetched", "schema_profiled", "source_tied", "rights_reviewed")})
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--edinet-date", required=True, type=date.fromisoformat)
    parser.add_argument("--edinet-secret-env", help="Explicitly approved secret setting name, never its value")
    args = parser.parse_args()
    run(args.private_dir, args.snapshot, args.edinet_date, args.edinet_secret_env)
