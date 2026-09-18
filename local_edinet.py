"""Read-only adapter for an explicitly selected preexisting EDINET archive."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from evidence_core import ContractError
from filing_catalog import edinet_metadata, numad_sample
from original_tie import compare_zip
from source_acquisition import encoded, gate, safe_uri, sha256, utcnow


class LocalArchive:
    def __init__(self, root, store, *, provenance_class="preexisting_local_official_archive"):
        path = Path(root)
        if not path.is_absolute():
            raise ContractError("local_root_must_be_absolute")
        self.root = path.resolve()
        self._outside_git(self.root)
        if not self.root.is_dir():
            raise ContractError("local_root_not_available")
        if store.root == self.root or self.root in store.root.parents:
            raise ContractError("audit_store_must_not_modify_local_archive")
        if provenance_class not in {"preexisting_local_official_archive", "synthetic_fixture"}:
            raise ContractError("invalid_local_provenance")
        self.provenance_class = provenance_class
        self.store = store
        self.root_id = sha256(str(self.root).encode("utf-8"))

    @staticmethod
    def _outside_git(path):
        if any((p / ".git").exists() for p in (path, *path.parents)):
            raise ContractError("local_archive_inside_git_checkout")

    def _path(self, relative):
        path = (self.root / relative).resolve()
        if self.root not in path.parents:
            raise ContractError("local_path_outside_explicit_root")
        self._outside_git(path.parent)
        if not path.is_file():
            raise ContractError("local_file_not_available")
        return path

    def _bytes(self, relative):
        path = self._path(relative)
        try:
            before = path.stat()
            if before.st_size > 32 * 1024 * 1024:
                raise ContractError("local_artifact_size_limit")
            data = path.read_bytes()
            after = path.stat()
        except OSError:
            raise ContractError("local_file_read_failed") from None
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ContractError("local_file_changed_during_read")
        return data, after

    def zip_index(self, preferred_doc_id=None):
        if preferred_doc_id and re.fullmatch(r"S[0-9A-Z]{7}", preferred_doc_id):
            direct = [p for p in (f"documents/{preferred_doc_id}.zip", f"{preferred_doc_id}.zip")
                      if (self.root / p).is_file()]
            if direct:
                for relative in direct:
                    self._path(relative)
                return {preferred_doc_id: direct}
        index = {}
        for path in self.root.rglob("*.zip"):
            if re.fullmatch(r"S[0-9A-Z]{7}", path.stem):
                self._path(path.relative_to(self.root))
                index.setdefault(path.stem, []).append(path.relative_to(self.root).as_posix())
        return {doc: sorted(paths) for doc, paths in index.items()}

    def observe(self, relative, *, doc_id=None):
        path = self._path(relative)
        if doc_id is not None and path.stem != doc_id:
            raise ContractError("local_document_id_mismatch")
        data, stat = self._bytes(relative)
        digest = sha256(data)
        sidecar = path.with_suffix(".manifest.json")
        log_hash, retrieved, interface = None, None, None
        reason = "original_acquisition_log_not_available"
        if sidecar.exists():
            log_bytes, _ = self._bytes(sidecar.relative_to(self.root))
            log_hash = sha256(log_bytes)
            try:
                log = json.loads(log_bytes)
                if log.get("doc_id") != doc_id:
                    raise ContractError("local_log_document_id_mismatch")
                if log.get("sha256") != digest or log.get("bytes") != len(data):
                    raise ContractError("local_log_byte_integrity_failure")
                reason = "original_acquisition_log_not_validated"
                endpoint = log.get("endpoint", "")
                if endpoint.startswith("/api/v2/"):
                    endpoint = "https://api.edinet-fsa.go.jp" + endpoint
                endpoint = safe_uri(endpoint)
                expected = (f"https://api.edinet-fsa.go.jp/api/v2/documents/{doc_id}"
                            if doc_id else "https://api.edinet-fsa.go.jp/api/v2/documents.json")
                if (endpoint.split("?", 1)[0] == expected and log.get("http_status") == 200
                        and log.get("source") == "EDINET official API v2"):
                    timestamp = datetime.fromisoformat(log["retrieved_at"])
                    if timestamp.tzinfo is not None and timestamp.utcoffset() is not None:
                        retrieved, interface, reason = timestamp.isoformat(), "edinet-api-v2", None
            except (json.JSONDecodeError, TypeError, KeyError):
                raise ContractError("local_log_schema_mismatch") from None
            except ValueError as exc:
                if isinstance(exc, ContractError):
                    raise
                raise ContractError("local_log_schema_mismatch") from None
        identity = {"archive_root_id": self.root_id, "relative_path": path.relative_to(self.root).as_posix(),
                    "doc_id": doc_id, "byte_sha256": digest, "byte_count": len(data),
                    "source_mtime_ns": stat.st_mtime_ns, "acquisition_log_sha256": log_hash,
                    "provenance_class": self.provenance_class}
        checkpoint = f"local_completed/{sha256(encoded(identity))}.json"
        cached = self.store.root / checkpoint
        if cached.exists():
            result = json.loads(cached.read_bytes())
            self.read(result)
            return result
        result = dict(identity, status="OBSERVED", acquisition_method="preexisting_local_archive",
            observed_at=utcnow(), source_mtime=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            original_provider_retrieved_at=retrieved, original_provider_retrieved_at_missing_reason=reason,
            provider_timestamp_basis="matching_local_log_claim" if retrieved else None,
            provider_version=None, provider_version_missing_reason="archive_release_unknown",
            interface_version=interface, export_allowed=False)
        self.store.record("local_manifests", result)
        self.store.publish(checkpoint, encoded(result))
        return result

    def read(self, artifact):
        if artifact["archive_root_id"] != self.root_id:
            raise ContractError("local_archive_root_mismatch")
        data, _ = self._bytes(artifact["relative_path"])
        if len(data) != artifact["byte_count"] or sha256(data) != artifact["byte_sha256"]:
            raise ContractError("local_byte_integrity_failure")
        return data

    def daily_metadata(self, row):
        day = row["submit_date"]
        names = {f"list_{day}.json", f"{day}.json", "documents.json"}
        direct = [self.root / p for p in (f"listings/{day}/list_{day}.json", f"listings/{day}/documents.json",
                  f"{day}/documents.json", f"{day}.json", f"list_{day}.json")]
        candidates = sorted(p for p in direct if p.is_file())
        if not candidates:
            candidates = sorted(p for p in self.root.rglob("*.json") if p.name in names)
        for path in candidates:
            data, _ = self._bytes(path.relative_to(self.root))
            try:
                payload = json.loads(data)
                if payload.get("metadata", {}).get("parameter", {}).get("date") != day:
                    continue
                rows, profile = edinet_metadata(data)
                artifact = self.observe(path.relative_to(self.root))
                matches = [r for r in rows if r["docID"] == row["doc_id"]]
                return gate(None if matches else "local_daily_document_id_not_found",
                            artifact=artifact, schema_profile=profile, doc_id=row["doc_id"],
                            daily_sequences=[r["seqNumber"] for r in matches])
            except (ValueError, TypeError):
                return gate("local_daily_metadata_invalid")
        return gate("local_daily_metadata_not_available")


def select_sample(first_bytes, index, full_bytes=None):
    """Prefer line 1. Otherwise smallest common doc_id, then its first row; no tie cherry-picking."""
    first, profile = numad_sample(first_bytes)
    if first["doc_id"] in index:
        return first, profile, {"numad_file": "yuho-2022.jsonl", "line_number": 1,
            "doc_id": first["doc_id"], "selection_rule": "prefer_fixed_line_1_if_local_zip_exists"}
    if full_bytes is None:
        return None
    common = {}
    try:
        for number, line in enumerate(full_bytes.splitlines(), 1):
            row = json.loads(line)
            if row.get("doc_id") in index:
                common.setdefault(row["doc_id"], (number, line))
    except (ValueError, AttributeError):
        raise ContractError("numad_intersection_schema_mismatch") from None
    if not common:
        raise ContractError("no_numad_local_document_intersection")
    doc = min(common)
    number, line = common[doc]
    row, profile = numad_sample(line + b"\n")
    profile["sample_locator"] = f"jsonl:line:{number}"
    return row, profile, {"numad_file": "yuho-2022.jsonl", "line_number": number,
        "doc_id": doc, "selection_rule": "sorted_intersection_doc_id_then_first_line",
        "intersection_doc_ids": sorted(common)}


def audit_local(archive, row, index):
    result = {"local_official_original_located": gate("local_original_not_available"),
              "local_official_original_byte_integrity": gate("local_original_not_available"),
              "local_official_original_tied": gate("local_original_not_available"),
              "local_official_metadata_tied": archive.daily_metadata(row)}
    paths = index.get(row["doc_id"], [])
    if not paths:
        return result
    result["local_official_original_located"] = gate(doc_id=row["doc_id"])
    try:
        if len(paths) != 1:
            raise ContractError("ambiguous_local_document_versions")
        artifact = archive.observe(paths[0], doc_id=row["doc_id"])
        data = archive.read(artifact)
        result["artifact"] = artifact
        result["local_official_original_byte_integrity"] = gate(byte_sha256=artifact["byte_sha256"],
            byte_count=artifact["byte_count"], basis="observed_bytes_and_optional_local_log")
        result["local_official_original_tied"] = compare_zip(data, row, artifact)
    except ContractError as exc:
        result["local_official_original_byte_integrity"] = gate(str(exc))
        result["local_official_original_tied"] = gate(str(exc))
    return result
