"""Source-specific schema checks and dated identity contracts (no inferred joins)."""
from dataclasses import asdict, dataclass
from datetime import date, datetime
import json
import re

from evidence_core import ContractError, aware
from source_acquisition import encoded, sha256


def check_code(value, pattern):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(pattern, value)):
        raise ContractError("Identifier schema mismatch")


@dataclass(frozen=True)
class Entity:
    entity_id: str


@dataclass(frozen=True)
class Security:
    security_id: str
    issuer_entity_id: str
    security_type: str


@dataclass(frozen=True)
class IdentityVersion:
    """Half-open valid/recorded intervals; unknown validity never matches as-of.

    name is an attribute, not a join key. EDINET/JCN attach to entities; security
    codes attach to securities. Filer/issuer/subject are separate filing roles.
    """
    owner_id: str
    owner_kind: str
    scheme: str
    value: str
    valid_from: date | None
    valid_to: date | None
    recorded_from: datetime
    recorded_to: datetime | None
    evidence_sha256: str
    matching_method: str
    missing_reason: str | None = None

    def __post_init__(self):
        aware(self.recorded_from)
        if self.recorded_to is not None and aware(self.recorded_to) <= self.recorded_from:
            raise ContractError("Invalid recorded interval")
        if (self.valid_from is None) != bool(self.missing_reason):
            raise ContractError("Unknown validity requires a reason")
        if self.valid_to is not None and (self.valid_from is None or self.valid_to <= self.valid_from):
            raise ContractError("Invalid validity interval")
        if self.scheme not in {"edinet", "jcn", "security_code", "name"}:
            raise ContractError("Unknown identifier scheme")
        kind = "security" if self.scheme == "security_code" else "entity"
        if self.owner_kind != kind or not self.owner_id or not self.value or not self.matching_method:
            raise ContractError("Identity owner/method required")
        if self.scheme == "security_code":
            check_code(self.value, r"[0-9A-Z]{4,5}")
        if self.scheme == "edinet":
            check_code(self.value, r"E\d{5}")
        if self.scheme == "jcn":
            check_code(self.value, r"\d{13}")
        check_code(self.evidence_sha256, r"[0-9a-f]{64}")
        if self.evidence_sha256 is None:
            raise ContractError("Evidence hash required")

    def active(self, day, recorded_at):
        aware(recorded_at)
        return (self.valid_from is not None and self.valid_from <= day
                and (self.valid_to is None or day < self.valid_to)
                and self.recorded_from <= recorded_at
                and (self.recorded_to is None or recorded_at < self.recorded_to))


def save_master(store, entities, securities, history):
    entity_ids = {x.entity_id for x in entities}
    security_ids = {x.security_id for x in securities}
    if (len(entity_ids) != len(entities) or len(security_ids) != len(securities)
            or entity_ids & security_ids or "" in entity_ids or "" in security_ids):
        raise ContractError("Duplicate/invalid master ID")
    if any(s.issuer_entity_id not in entity_ids or not s.security_type for s in securities):
        raise ContractError("Unknown security issuer/type")
    for item in history:
        if item.owner_id not in (entity_ids if item.owner_kind == "entity" else security_ids):
            raise ContractError("Unknown identity owner")
    def serial(item):
        return {k: v.isoformat() if isinstance(v, (date, datetime)) else v
                for k, v in asdict(item).items()}
    return store.record("masters", {"entities": [asdict(x) for x in entities],
        "securities": [asdict(x) for x in securities],
        "identifier_history": [serial(x) for x in history]})


def resolve_identifier(history, scheme, value, day, recorded_at):
    if scheme == "name":
        raise ContractError("Names are not identity join keys")
    owners = {x.owner_id for x in history if x.scheme == scheme and x.value == value
              and x.active(day, recorded_at)}
    if len(owners) > 1:
        raise ContractError("Ambiguous dated identifier")
    return next(iter(owners), None)


def profile_rows(rows):
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ContractError("Missing records")
    types = {key: sorted({type(row.get(key)).__name__ for row in rows})
             for key in sorted(set().union(*(row.keys() for row in rows)))}
    return {"row_count": len(rows), "columns": types, "schema_sha256": sha256(encoded(types))}


NUMAD_COLUMNS = {"company_name", "document_name", "doc_id", "sec_code", "edinet_code",
                 "period_end", "period_start", "submit_date", "JCN", "tag", "text", "url"}


def numad_sample(data):
    """Profile only the first complete JSONL row; never treat a prefix as a full file."""
    if b"\n" not in data:
        raise ContractError("Incomplete JSONL sample")
    try:
        row = json.loads(data.split(b"\n", 1)[0])
        if not isinstance(row, dict) or not NUMAD_COLUMNS <= row.keys():
            raise ContractError("Missing numad columns")
        for key in NUMAD_COLUMNS:
            if not isinstance(row[key], str) and not (key in {"sec_code", "JCN"} and row[key] is None):
                raise ContractError("numad column type mismatch")
        check_code(row["doc_id"], r"S[0-9A-Z]{7}")
        check_code(row["edinet_code"], r"E\d{5}")
        check_code(row["sec_code"], r"[0-9A-Z]{4,5}")
        check_code(row["JCN"], r"\d{13}")
        start, end = date.fromisoformat(row["period_start"]), date.fromisoformat(row["period_end"])
        date.fromisoformat(row["submit_date"])
        if end < start or not row["tag"] or not row["text"]:
            raise ContractError("Invalid period or empty text")
    except (ValueError, TypeError, KeyError):
        raise ContractError("numad schema mismatch") from None
    return row, dict(profile_rows([row]), sampled_rows=1, full_file_profiled=False,
                     sample_locator="jsonl:line:1", doc_ids=[row["doc_id"]])


EDINET_COLUMNS = {"docID", "edinetCode", "secCode", "JCN", "filerName", "issuerEdinetCode",
                  "subjectEdinetCode", "parentDocID", "submitDateTime", "opeDateTime",
                  "withdrawalStatus", "docInfoEditStatus", "disclosureStatus"}


def edinet_metadata(data):
    try:
        payload = json.loads(data)
        metadata, rows = payload["metadata"], payload["results"]
        if metadata["status"] != "200" or not isinstance(rows, list):
            raise ContractError("EDINET application status/schema mismatch")
        if type(metadata["resultset"]["count"]) is not int or metadata["resultset"]["count"] != len(rows):
            raise ContractError("EDINET count mismatch")
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or not (EDINET_COLUMNS | {"seqNumber"}) <= row.keys():
                raise ContractError("Missing EDINET columns")
            if any(row[k] is not None and not isinstance(row[k], str) for k in EDINET_COLUMNS):
                raise ContractError("EDINET column type mismatch")
            check_code(row["docID"], r"S[0-9A-Z]{7}")
            if (row["docID"] is None or type(row["seqNumber"]) is not int
                    or row["seqNumber"] < 1 or row["seqNumber"] in seen):
                raise ContractError("Missing document ID or invalid/duplicate daily sequence")
            seen.add(row["seqNumber"])
            check_code(row["secCode"], r"[0-9A-Z]{4,5}")
            for key in ("edinetCode", "issuerEdinetCode", "subjectEdinetCode"):
                check_code(row[key], r"E\d{5}")
            check_code(row["parentDocID"], r"S[0-9A-Z]{7}")
            for key, allowed in (("withdrawalStatus", {"0", "1", "2"}),
                                 ("docInfoEditStatus", {"0", "1", "2"}),
                                 ("disclosureStatus", {"0", "1", "2", "3"})):
                if row[key] not in allowed:
                    raise ContractError("Unknown document status")
        profile = profile_rows(rows) if rows else {"row_count": 0, "columns": None,
            "schema_sha256": None, "missing_reason": "no_rows_to_profile"}
        return rows, profile
    except (ValueError, TypeError, KeyError):
        raise ContractError("EDINET metadata schema mismatch") from None


def save_filings(store, rows, artifact, previous=None):
    """Keep provider fields and role separation; missing rows are not withdrawals."""
    if edinet_metadata(store.read_raw(artifact))[0] != rows:
        raise ContractError("Rows do not match source bytes")
    scope = {"source_id": artifact["source_id"], "safe_url": artifact["safe_url"]}
    if previous is None:
        candidates = [json.loads(path.read_bytes()) for path in (store.root / "filings").glob("*.json")]
        candidates = [x for x in candidates if x["scope"] == scope]
        same = [x for x in candidates if x["acquisition_task_id"] == artifact["task_id"]]
        if same:
            return same[0]
        previous = max(candidates, key=lambda x: (x["recorded_at"], x["revision"]), default=None)
    if previous and previous["scope"] != scope:
        raise ContractError("Cannot diff different daily sources")
    filings = []
    for row in rows:
        filings.append({"doc_id": row["docID"], "daily_sequence": row["seqNumber"], "provider_fields": row,
            "filer_edinet_code": row["edinetCode"], "issuer_edinet_code": row["issuerEdinetCode"],
            "subject_edinet_code": row["subjectEdinetCode"], "parent_doc_id": row["parentDocID"],
            "recorded_at": artifact["retrieved_at"], "source_artifact_sha256": artifact["byte_sha256"],
            "public_time_source": "submitDateTime", "provider_available_at": None,
            "missing_reasons": {k: "provider_null" for k, v in row.items() if v is None}})
    old = {row["daily_sequence"]: row["provider_fields"] for row in (previous or {}).get("filings", [])}
    new = {row["seqNumber"]: row for row in rows}
    changes = [{"doc_id": new[seq]["docID"], "daily_sequence": seq,
                "kind": "changed" if seq in old else "added",
                "fields": sorted(k for k in new[seq] if old.get(seq, {}).get(k) != new[seq][k])}
               for seq in sorted(new) if old.get(seq) != new[seq]]
    changes += [{"doc_id": old[seq]["docID"], "daily_sequence": seq,
                 "kind": "absent_from_snapshot", "reason": "not_inferred_withdrawn"}
                for seq in sorted(old.keys() - new.keys())]
    snapshot = {"artifact_sha256": artifact["byte_sha256"], "filings": filings,
                "acquisition_task_id": artifact["task_id"],
                "revision": previous["revision"] + 1 if previous else 0,
                "scope": scope, "recorded_at": artifact["retrieved_at"],
                "previous_snapshot_sha256": sha256(encoded(previous)) if previous else None,
                "changes": changes}
    store.record("filings", snapshot)
    return snapshot
