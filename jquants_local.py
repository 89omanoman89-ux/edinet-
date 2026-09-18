"""Read-only, bounded J-Quants CSV evidence. No credentials or network code."""
import csv
from datetime import date
import gzip
import io
import json
from pathlib import Path
import re
import zlib

from evidence_core import ContractError
from metadata_gap_audit import ReadOnlyEvidence
from source_acquisition import encoded, sha256, utcnow

DATASETS = {
    "equities_master": {"Date", "Code", "Mkt", "ProdCat"},
    "equities_bars_daily": {"Date", "Code", "O", "H", "L", "C", "Vo", "AdjFactor"},
    "fins_summary": {"DiscDate", "DiscTime", "Code", "DiscNo", "DocType", "CurPerSt", "CurPerEn"},
    "markets_calendar": {"Date", "HolDiv"},
}


def code(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9A-Z]{4,5}", value):
        raise ContractError("invalid_security_code")
    return value  # No integer conversion, padding, truncation or name join.


def csv_rows(raw, compressed=True):
    try:
        data = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(256*1024*1024+1) if compressed else raw
        if len(data) > 256*1024*1024: raise ContractError("csv_expansion_limit")
        reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
        fields = reader.fieldnames
        if not fields or len(fields) != len(set(fields)): raise ContractError("invalid_csv_header")
        for n, row in enumerate(reader, 1):
            if None in row or None in row.values(): raise ContractError("invalid_csv_row_width")
            yield fields, n, row
    except (OSError, EOFError, UnicodeError, csv.Error, zlib.error):
        raise ContractError("invalid_compressed_csv") from None


class JQuantsArchive(ReadOnlyEvidence):
    def __init__(self, root, store, *, synthetic=False):
        super().__init__(root, store, provenance_class="synthetic_fixture" if synthetic else "preexisting_local_official_archive")
        self.synthetic = synthetic

    def evidence(self, relative):
        raw, st = self._bytes(relative)
        return raw, {"root_id": self.root_id, "relative_path": relative, "byte_sha256": sha256(raw),
            "byte_count": len(raw), "source_mtime_ns": st.st_mtime_ns, "observed_at": utcnow(),
            "acquisition_method": "preexisting_local_jquants_archive", "synthetic": self.synthetic,
            "original_provider_retrieved_at": None, "provider_version": None,
            "missing_reasons": ["per_file_acquisition_time_not_recorded", "provider_version_not_recorded"],
            "rights_review": "BLOCKED", "export_allowed": False}

    def plan(self, windows):
        """One explicitly located revision per dataset; never resolve a mutable latest pointer."""
        manifests, files = [], []
        for dataset in DATASETS:
            matches = sorted((self.root / dataset).glob("revision=*/manifest.json"))
            if len(matches) != 1: raise ContractError("jquants_manifest_missing_or_ambiguous:" + dataset)
            path = matches[0]; relative = path.relative_to(self.root).as_posix()
            raw, artifact = self.evidence(relative)
            try: manifest = json.loads(raw)
            except ValueError: raise ContractError("jquants_manifest_invalid") from None
            if manifest.get("dataset") != dataset or not isinstance(manifest.get("files"), list):
                raise ContractError("jquants_manifest_schema_invalid")
            manifests.append({"dataset": dataset, "artifact": artifact,
                "local_revision": manifest.get("revision"), "local_batch_completed_at": manifest.get("created_at_utc"),
                "api_endpoint_claim": manifest.get("endpoint"), "local_manifest_schema_version": manifest.get("schema_version"),
                "declared_file_count": len(manifest["files"]), "declared_date_range": [manifest.get("minimum_date"), manifest.get("maximum_date")]})
            for f in manifest["files"]:
                lo, hi = f.get("minimum_date"), f.get("maximum_date")
                if not lo or not hi: raise ContractError("manifest_file_date_range_missing")
                date.fromisoformat(lo); date.fromisoformat(hi)
                selected = dataset == "markets_calendar" or any(lo <= end and start <= hi for start, end in windows[dataset])
                if not selected: continue
                relative = (path.parent / f["file"]).relative_to(self.root).as_posix()
                self._path(relative)
                files.append({"dataset": dataset, "relative_path": relative, "expected_sha256": f.get("sha256"),
                    "expected_bytes": f.get("bytes"), "local_revision": manifest.get("revision"),
                    "provider_last_modified_claim": f.get("last_modified"), "manifest_artifact": artifact})
        return {"scope": "fixed_P3_dates_and_codes_only", "selection_basis": "saved_manifest_date_claims_verified_for_selected_files",
                "windows": windows, "manifests": manifests, "files": files}

    def inspect(self, selected_file, keep):
        raw, artifact = self.evidence(selected_file["relative_path"])
        if not selected_file.get("expected_sha256") or selected_file.get("expected_bytes") is None:
            raise ContractError("source_manifest_integrity_missing")
        if (artifact["byte_sha256"], len(raw)) != (selected_file["expected_sha256"], selected_file["expected_bytes"]):
            raise ContractError("jquants_byte_integrity_failed")
        dataset = selected_file["dataset"]; kept, days, fields, count, invalid_codes = [], set(), [], 0, 0
        for fields, n, row in csv_rows(raw, selected_file["relative_path"].endswith(".gz")):
            if not DATASETS[dataset] <= set(fields): raise ContractError("unsupported_jquants_schema")
            day = row["DiscDate" if dataset == "fins_summary" else "Date"]
            try: date.fromisoformat(day)
            except ValueError: raise ContractError("invalid_jquants_date") from None
            count += 1; days.add(day)
            if "Code" in row:
                try: code(row["Code"])
                except ContractError: invalid_codes += 1
            if keep(row):
                locator = {"artifact": artifact, "record_index": n, "record_index_basis": "one_based_data_record_excluding_header",
                           "row_sha256": sha256(encoded(row))}
                kept.append({"observation_id": sha256(encoded([artifact["byte_sha256"], n, locator["row_sha256"]])),
                    "dataset": dataset, "provider_fields": row, "source": locator, "synthetic": self.synthetic})
        if not count: raise ContractError("empty_jquants_csv")
        profile = dict(selected_file, artifact=artifact, row_count=count, row_count_basis="csv_records_recounted",
            date_range=[min(days), max(days)], fields=fields, schema_sha256=sha256(encoded(fields)),
            code_schema="string_4_or_5_ASCII_uppercase_alphanumeric", invalid_code_rows=invalid_codes,
            retained_rows=len(kept), api_schema_profile="jquants_v2_bulk_observed_v1",
            price_columns=[x for x in fields if x in {"O", "H", "L", "C", "AdjO", "AdjH", "AdjL", "AdjC"}],
            corporate_action_columns=[x for x in fields if x in {"AdjFactor", "ExRT"}],
            price_basis="reported_unadjusted" if dataset == "equities_bars_daily" else None,
            adjustment_basis="ex_date_factor_not_cumulative_not_total_return" if dataset == "equities_bars_daily" else None)
        return profile, kept

    def verify_rows(self, observations):
        grouped = {}
        for row in observations: grouped.setdefault(row["source"]["artifact"]["relative_path"], []).append(row)
        for relative, rows in grouped.items():
            raw, _ = self._bytes(relative)
            digest = sha256(raw)
            wanted = {r["source"]["record_index"]: [] for r in rows}
            for r in rows:
                if digest != r["source"]["artifact"]["byte_sha256"]: raise ContractError("source_changed_during_audit")
                wanted[r["source"]["record_index"]].append(r)
            found = set()
            for _, n, provider in csv_rows(raw, relative.endswith(".gz")):
                if n in wanted:
                    for r in wanted[n]:
                        if provider != r["provider_fields"] or sha256(encoded(provider)) != r["source"]["row_sha256"]:
                            raise ContractError("jquants_row_reverse_lookup_mismatch")
                        if r["observation_id"] != sha256(encoded([digest, n, sha256(encoded(provider))])):
                            raise ContractError("jquants_observation_id_mismatch")
                    found.add(n)
            if found != wanted.keys(): raise ContractError("jquants_source_locator_missing")
        return {"status": "PASS", "observations": len(observations), "files": len(grouped)}
