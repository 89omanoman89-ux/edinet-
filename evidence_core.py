"""Small, dependency-free research safety kernel; NOT a complete data platform.

No network clients or empirical market data are bundled. Test fixtures are synthetic.
The functions validate declared metadata; they cannot prove that metadata is truthful.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from math import isfinite, sqrt
from typing import Iterable, Literal

JST = timezone(timedelta(hours=9))


class ContractError(ValueError):
    """A data contract is violated: fail closed instead of inventing a value."""


def aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ContractError("Timezone-aware datetime required")
    return value


def availability_bound(day: date, exact_time: time | None = None,
                       latency: timedelta = timedelta(0)) -> datetime:
    """JST availability: unknown intraday time => NEXT midnight, not same-day 00:00.

    This is an explicit conservative assumption, not an observed publication time.
    Exchange sessions and order eligibility must be resolved by a separate calendar.
    """
    if isinstance(day, datetime) or not isinstance(day, date):
        raise ContractError("Expected a date, not a datetime")
    if latency < timedelta(0):
        raise ContractError("Latency must be nonnegative")
    if exact_time is not None and exact_time.tzinfo is not None:
        raise ContractError("Provide local JST time without a timezone")
    base = datetime.combine(day, exact_time or time(0), tzinfo=JST)
    if exact_time is None:
        base += timedelta(days=1)
    return base + latency


@dataclass(frozen=True)
class FactKey:
    entity_id: str
    metric_id: str
    period_start: date
    period_end: date
    period_kind: Literal["instant", "duration", "ytd"]
    scope: str
    accounting_standard: str
    unit: str
    dimensions: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not all((self.entity_id, self.metric_id, self.scope,
                    self.accounting_standard, self.unit)):
            raise ContractError("Fact key fields may not be empty")
        if self.period_end < self.period_start:
            raise ContractError("Reversed fiscal interval")
        if self.period_kind not in {"instant", "duration", "ytd"}:
            raise ContractError("Unknown period kind")
        if self.period_kind == "instant" and self.period_start != self.period_end:
            raise ContractError("Instant facts must use one date")
        if tuple(sorted(self.dimensions)) != self.dimensions:
            raise ContractError("Dimensions must be sorted")
        if len(dict(self.dimensions)) != len(self.dimensions):
            raise ContractError("Duplicate dimension name")


@dataclass(frozen=True)
class Observation:
    record_id: str
    source_id: str
    series_id: str  # explicit revision lineage, NOT guessed from company and year
    key: FactKey
    revision: int
    value: Decimal | None
    missing_reason: str | None
    available_at: datetime | None
    availability_basis: Literal["exact", "date_upper_bound", "unknown"]
    recorded_at: datetime
    representation: str  # reported, guidance, derived, proxy, imputed, model, legacy_claim
    extraction_method: str  # structured, deterministic, manual, text_parser, llm, none
    verification: Literal["unverified", "source_tied", "recomputed"]
    source_artifact_sha256: str
    source_locator: str
    source_document_id: str
    synthetic: bool
    state: Literal["active", "withdrawn"] = "active"
    input_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all((self.record_id, self.source_id, self.series_id,
                    self.source_document_id, self.source_locator)):
            raise ContractError("Provenance identifiers are required")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 0:
            raise ContractError("Revision must be a nonnegative integer")
        aware(self.recorded_at)
        if self.available_at is not None:
            aware(self.available_at)
        if self.availability_basis not in {"exact", "date_upper_bound", "unknown"}:
            raise ContractError("Unknown availability basis")
        if (self.available_at is None) != (self.availability_basis == "unknown"):
            raise ContractError("Unknown timing must have no available_at")
        if self.value is not None and (not isinstance(self.value, Decimal) or not self.value.is_finite()):
            raise ContractError("Values must be finite Decimal or None")
        if (self.value is None) != bool(self.missing_reason):
            raise ContractError("Null requires a reason; a value must not have one")
        if self.state not in {"active", "withdrawn"}:
            raise ContractError("Unknown row state")
        if self.state == "withdrawn" and (self.value is not None or self.missing_reason != "withdrawn"):
            raise ContractError("Withdrawal is a tombstone, not a numeric zero")
        if self.representation not in {"reported", "guidance", "derived", "proxy", "imputed", "model", "legacy_claim"}:
            raise ContractError("Unknown representation")
        if self.extraction_method not in {"structured", "deterministic", "manual", "text_parser", "llm", "none"}:
            raise ContractError("Unknown extraction method")
        if self.verification not in {"unverified", "source_tied", "recomputed"}:
            raise ContractError("Unknown verification status")
        if not isinstance(self.synthetic, bool):
            raise ContractError("synthetic must be an explicit boolean")
        if len(self.source_artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.source_artifact_sha256):
            raise ContractError("A lowercase SHA-256 is required")
        if self.representation == "derived" and not self.input_ids:
            raise ContractError("Derived values need input lineage")


@dataclass(frozen=True)
class Selection:
    observations: tuple[Observation, ...]
    blocked: tuple[tuple[str, str], ...]  # record id / reason; must be reported downstream


def select_asof(observations: Iterable[Observation], decision_at: datetime,
                snapshot_cutoff: datetime, *,
                mode: Literal["public_reconstruction", "system_replay"] = "public_reconstruction",
                allowed_representations: frozenset[str] = frozenset({"reported"}),
                allowed_methods: frozenset[str] = frozenset({"structured", "deterministic", "manual"}),
                allow_synthetic_for_tests: bool = False) -> Selection:
    """Select known revision within each source + explicitly defined series.

    public_reconstruction uses historically public information reconstructed NOW;
    system_replay also requires it to have been recorded by the decision time.
    Unknown publication timing blocks its entire series, conservatively.
    Source reconciliation, issuer/security mapping and exchange execution are NOT
    performed here. A blocked revision never falls back silently to an older value.
    """
    aware(decision_at); aware(snapshot_cutoff)
    if mode not in {"public_reconstruction", "system_replay"}:
        raise ContractError("Unknown replay mode")
    if snapshot_cutoff < decision_at:
        raise ContractError("Snapshot cutoff must cover the decision time")
    groups: dict[tuple[str, str], list[Observation]] = {}
    ids: set[str] = set()
    for o in observations:
        if o.record_id in ids:
            raise ContractError("Duplicate record id")
        ids.add(o.record_id)
        if o.recorded_at > snapshot_cutoff:
            continue
        if mode == "system_replay" and o.recorded_at > decision_at:
            continue
        groups.setdefault((o.source_id, o.series_id), []).append(o)
    chosen: list[Observation] = []
    blocked: list[tuple[str, str]] = []
    for group_id in sorted(groups):
        rows = groups[group_id]
        if len({o.key for o in rows}) != 1:
            raise ContractError("Revision series changed semantic dimensions")
        unknown = [o for o in rows if o.available_at is None]
        if unknown:
            blocked.extend((o.record_id, "unknown_availability_blocks_series") for o in unknown)
            continue
        visible = [o for o in rows if o.available_at < decision_at]
        if not visible:
            continue
        latest_revision = max(o.revision for o in visible)
        candidates = [o for o in visible if o.revision == latest_revision]
        latest_recorded = max(o.recorded_at for o in candidates)
        winners = [o for o in candidates if o.recorded_at == latest_recorded]
        if len(winners) != 1:
            raise ContractError("Ambiguous revision: do not use arbitrary row ordering")
        o = winners[0]
        reason = None
        if o.state == "withdrawn": reason = "withdrawn"
        elif o.value is None: reason = o.missing_reason
        elif o.synthetic and not allow_synthetic_for_tests: reason = "synthetic_not_empirical"
        elif o.representation not in allowed_representations: reason = "representation_not_allowed"
        elif o.extraction_method not in allowed_methods: reason = "extraction_method_not_allowed"
        elif o.verification not in {"source_tied", "recomputed"}: reason = "unverified"
        if reason:
            blocked.append((o.record_id, reason))
        else:
            chosen.append(o)
    return Selection(tuple(chosen), tuple(blocked))


@dataclass(frozen=True)
class DerivedQuarter:
    value: Decimal
    period_start: date
    period_end: date
    available_at: datetime
    input_ids: tuple[str, str]
    synthetic: bool
    definition: str = "standalone_from_ytd.v1"


def quarter_from_ytd(current: Observation, previous: Observation,
                     quarter_start: date) -> DerivedQuarter:
    """Only subtract comparable reported YTD values; do not infer missing quarters.

    Callers must first select source-tied vintages with select_asof; no old quarter
    is backdated when an earlier cumulative value was only restated later.
    """
    a, b = current.key, previous.key
    comparable_a = (a.entity_id, a.metric_id, a.period_start, a.scope, a.accounting_standard, a.unit, a.dimensions)
    comparable_b = (b.entity_id, b.metric_id, b.period_start, b.scope, b.accounting_standard, b.unit, b.dimensions)
    if comparable_a != comparable_b or current.source_id != previous.source_id:
        raise ContractError("Non-comparable YTD facts")
    if a.period_kind != "ytd" or b.period_kind != "ytd":
        raise ContractError("Both inputs must be cumulative flow facts")
    if b.period_end + timedelta(days=1) != quarter_start or not b.period_end < a.period_end:
        raise ContractError("The previous cumulative period must end immediately before this quarter")
    for o in (current, previous):
        if (o.state != "active" or o.value is None or o.available_at is None or
            o.representation != "reported" or o.verification not in {"source_tied", "recomputed"} or
            o.extraction_method not in {"structured", "manual"}):
            raise ContractError("Quarter inputs must be complete, verified, directly reported facts")
    return DerivedQuarter(current.value - previous.value, quarter_start, a.period_end,
                          max(current.available_at, previous.available_at),
                          (current.record_id, previous.record_id), current.synthetic or previous.synthetic)


@dataclass(frozen=True)
class Episode:
    episode_id: str
    decision_at: datetime
    outcome_end: datetime
    label_available_at: datetime | None

    def __post_init__(self) -> None:
        aware(self.decision_at); aware(self.outcome_end)
        if self.outcome_end < self.decision_at:
            raise ContractError("Outcome ends before the decision")
        if self.label_available_at is not None:
            aware(self.label_available_at)
            if self.label_available_at < self.outcome_end:
                raise ContractError("Outcome labels cannot be known before their window ends")


def past_training_ids(episodes: Iterable[Episode], validation_start: datetime,
                      gap: timedelta = timedelta(0)) -> tuple[str, ...]:
    """Past-only temporal split with label maturity and overlap guards.

    gap is a pre-validation exclusion gap, NOT a general post-test embargo.
    Partition calendar dates first; use separate folds for tuning/calibration.
    """
    aware(validation_start)
    if gap < timedelta(0):
        raise ContractError("Negative gap")
    boundary = validation_start - gap
    rows = list(episodes)
    if len({r.episode_id for r in rows}) != len(rows):
        raise ContractError("Duplicate episode ids")
    return tuple(sorted(r.episode_id for r in rows
                        if r.decision_at < boundary and r.outcome_end < boundary
                        and r.label_available_at is not None
                        and r.label_available_at < boundary))


def checked_standard_error(variance: float) -> float:
    """Negative cluster variance is a diagnostic failure, never silently clipped."""
    if not isfinite(variance) or variance < 0:
        raise ContractError("Invalid variance: report estimator/cluster diagnostics")
    return sqrt(variance)
