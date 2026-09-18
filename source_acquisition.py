"""Bounded, local-only P0/P1 acquisition. No source is approved by downloading it."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from evidence_core import ContractError


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def safe_uri(url):
    """Keep only validated EDINET date/type parameters; discard credentials/fragments."""
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        raise ContractError("HTTPS URL without userinfo required")
    query = [(k, v) for k, v in parse_qsl(p.query)
             if (k == "date" and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v))
             or (k == "type" and v in {"1", "2", "3", "4", "5"})]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), ""))


class PrivateStore:
    """Content-addressed bytes and immutable JSON records. Single local writer.

    Completed requests are checkpoints. An interrupted transfer is re-fetched in
    full; no partial transfer is promoted to an artifact. os.link publishes an
    fsynced temporary file without replacing an existing destination.
    """
    def __init__(self, root, repository=None):
        self.root = Path(root).resolve()
        repository = Path(repository or Path(__file__).parent).resolve()
        if self.root == repository or repository in self.root.parents:
            raise ContractError("Data must be outside the repository")
        if any((p / ".git").exists() for p in (self.root, *self.root.parents)):
            raise ContractError("Data must be outside any Git checkout")
        self.root.mkdir(parents=True, exist_ok=True)

    def publish(self, relative, data):
        dest = (self.root / relative).resolve()
        if self.root not in dest.parents:
            raise ContractError("Invalid store path")
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".pending-", dir=dest.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(name, dest)
            except FileExistsError:
                if dest.read_bytes() != data:
                    raise ContractError("Immutable path conflict") from None
        finally:
            Path(name).unlink(missing_ok=True)
        return relative

    def record(self, kind, value):
        data = encoded(value)
        return self.publish(f"{kind}/{sha256(data)}.json", data)

    def read_raw(self, manifest):
        digest = manifest.get("byte_sha256")
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            raise ContractError("Missing artifact hash")
        try:
            data = (self.root / "raw" / digest).read_bytes()
        except OSError:
            raise ContractError("Artifact missing") from None
        if sha256(data) != digest or len(data) != manifest["byte_count"]:
            raise ContractError("Artifact integrity failure")
        return data


@dataclass(frozen=True)
class Fetch:
    source_id: str
    url: str
    provider_version: str | None
    snapshot: str  # change explicitly to re-observe a mutable endpoint
    terms_url: str
    doc_id: str | None = None
    secret_name: str | None = None
    interface_version: str | None = None
    range_end: int | None = None  # inclusive, bounded prefix sampling only
    max_bytes: int = 8 * 1024 * 1024

    def identity(self):
        out = asdict(self)
        out["safe_url"] = safe_uri(out.pop("url"))
        out["terms_url"] = safe_uri(self.terms_url)
        if urlsplit(self.url).query != urlsplit(out["safe_url"]).query or urlsplit(self.url).fragment:
            raise ContractError("Only validated public query parameters allowed; use secret_getter for keys")
        if not self.source_id or not self.snapshot or not 0 < self.max_bytes <= 16 * 1024 * 1024:
            raise ContractError("Invalid bounded request")
        if self.range_end is not None and not 0 <= self.range_end < self.max_bytes:
            raise ContractError("Invalid sample range")
        if self.secret_name and (urlsplit(self.url).hostname != "api.edinet-fsa.go.jp"
                                 or urlsplit(self.url).port not in (None, 443)):
            raise ContractError("Credentials restricted to official EDINET")
        return out


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def transport(url, headers, limit, authenticated=False):
    opener = build_opener(NoRedirect()) if authenticated else build_opener()
    try:
        with opener.open(Request(url, headers=headers), timeout=30) as response:
            return response.status, dict(response.headers.items()), response.read(limit + 1)
    except HTTPError as exc:
        # Never persist an error body, URL or exception string: these may echo keys.
        headers = dict(exc.headers.items())
        exc.close()
        return exc.code, headers, b""


class Acquirer:
    def __init__(self, store, *, send=transport, sleep=time.sleep, now=utcnow,
                 secret_getter=None, min_interval=1.0, attempts=3):
        if min_interval < 0 or attempts < 1 or attempts > 5:
            raise ContractError("Invalid retry policy")
        self.store, self.send, self.sleep, self.now = store, send, sleep, now
        self.secret_getter = secret_getter
        self.min_interval, self.attempts = min_interval, attempts

    def fetch(self, task):
        identity = task.identity()
        task_id = sha256(encoded(identity))
        checkpoint = self.store.root / "completed" / f"{task_id}.json"
        if checkpoint.exists():
            result = json.loads(checkpoint.read_bytes())
            self.store.read_raw(result)
            return result
        for path in (self.store.root / "failures").glob("*.json"):
            failure = json.loads(path.read_bytes())
            if (failure["task_id"] == task_id and failure.get("retry_not_before")
                    and datetime.fromisoformat(failure["retry_not_before"]) > datetime.fromisoformat(self.now())):
                return failure
        result = dict(identity, task_id=task_id, status="BLOCKED", retrieved_at=None,
                      attempted_at=self.now(), byte_sha256=None, byte_count=None,
                      http_status=None, content_type=None, content_range=None,
                      missing_reason=None, attempts=[], export_allowed=False,
                      doc_id_missing_reason=(None if task.doc_id else "collection_or_documentation_artifact"),
                      provider_version_missing_reason=(None if task.provider_version
                                                       else "provider_version_unknown"))
        try:
            key = self.secret_getter(task.secret_name) if task.secret_name and self.secret_getter else None
        except Exception:
            # A secret manager failure may include secret material in its message.
            key = None
        if task.secret_name and not key:
            result["missing_reason"] = "approved_secret_not_configured"
            self.store.record("failures", result)
            return result
        url = task.url
        if key:
            url += ("&" if "?" in url else "?") + urlencode({"Subscription-Key": key})
        headers = {"User-Agent": "edinet-research-p0-p1/0.1", "Accept-Encoding": "identity"}
        if task.range_end is not None:
            headers["Range"] = f"bytes=0-{task.range_end}"
        for attempt in range(self.attempts):
            self.sleep(self.min_interval)
            status, response_headers, data = None, {}, b""
            try:
                status, response_headers, data = self.send(url, headers, task.max_bytes, bool(key))
                response_headers = {k.lower(): v for k, v in response_headers.items()}
                reason = self._validate(task, status, response_headers, data)
                if key and any(s.encode() in data or any(s in str(v) for v in response_headers.values())
                               for s in (key, urlencode({"k": key})[2:])):
                    reason = "credential_echo_rejected"
            except (URLError, TimeoutError, OSError, http.client.HTTPException):
                reason = "transport_failed"
            event = {"number": attempt + 1, "at": self.now(), "http_status": status,
                     "missing_reason": reason}
            self.store.record("attempts", dict(event, task_id=task_id))
            result["attempts"].append(event)
            result.update(http_status=status, missing_reason=reason)
            if reason is None:
                digest = sha256(data)
                self.store.publish(f"raw/{digest}", data)
                result.update(status="FETCHED", retrieved_at=self.now(), byte_sha256=digest,
                              byte_count=len(data), content_type=response_headers.get("content-type"),
                              content_range=response_headers.get("content-range"))
                self.store.record("manifests", result)
                self.store.publish(f"completed/{task_id}.json", encoded(result))
                return result
            if status not in (None, 429, 500, 502, 503, 504):
                break
            if attempt + 1 < self.attempts:
                delay = self._retry_delay(response_headers.get("retry-after"), attempt)
                # Do not retry early when a server asks for a long pause; resume later.
                if delay > 60:
                    result["missing_reason"] = "retry_after_deferred"
                    result["retry_after_seconds"] = delay
                    result["retry_not_before"] = (datetime.fromisoformat(self.now())
                                                   + timedelta(seconds=delay)).isoformat()
                    break
                self.sleep(delay)
        self.store.record("failures", result)
        return result

    def _retry_delay(self, value, attempt):
        try:
            delay = float(value)
        except (TypeError, ValueError):
            try:
                delay = (parsedate_to_datetime(value) - datetime.fromisoformat(self.now())).total_seconds()
            except (TypeError, ValueError, OverflowError):
                delay = 0
        return max(2 ** attempt, delay) if delay == delay and delay != float("inf") else 2 ** attempt

    @staticmethod
    def _validate(task, status, headers, data):
        if status in (401, 403):
            return "authentication_or_access_denied"
        if status not in (200, 206):
            return "http_failed"
        if len(data) > task.max_bytes:
            return "size_limit_exceeded"
        if headers.get("content-encoding", "identity").lower() != "identity":
            return "unexpected_content_encoding"
        if not data:
            return "empty_response"
        try:
            if "content-length" in headers and int(headers["content-length"]) != len(data):
                return "incomplete_response"
        except ValueError:
            return "invalid_content_length"
        if task.range_end is not None:
            match = re.fullmatch(r"bytes 0-(\d+)/(\d+)", headers.get("content-range", ""))
            if (status != 206 or not match or int(match[1]) != len(data) - 1
                    or int(match[1]) != min(task.range_end, int(match[2]) - 1)):
                return "invalid_sample_range"
        elif status != 200:
            return "unexpected_partial_response"
        return None


def gate(reason=None, **evidence):
    return {"status": "BLOCKED" if reason else "PASS", "reason": reason, **evidence}


def audit(source_id, *, docs, artifact, schema, tie, rights):
    return {"source_id": source_id, "production_approved": False, "export_allowed": False,
            "docs_checked": docs,
            "file_fetched": gate(artifact["missing_reason"],
                                 artifact_sha256=artifact["byte_sha256"]),
            "schema_profiled": schema, "source_tied": tie, "rights_reviewed": rights}
