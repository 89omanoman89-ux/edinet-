"""ALL values and issuer identifiers below are SYNTHETIC TEST FIXTURES.

Successful tests validate software behavior, not extraction accuracy or profitability.
"""
import unittest
from dataclasses import replace
from datetime import date, datetime, timedelta
from decimal import Decimal
from evidence_core import (JST, ContractError, FactKey, Observation, Episode,
    availability_bound, select_asof, quarter_from_ytd, past_training_ids,
    checked_standard_error)


def dt(month, day=1, hour=12):
    return datetime(2024, month, day, hour, tzinfo=JST)


def fixture(**changes):
    fields = dict(record_id="SYNTHETIC-1", source_id="synthetic-tests",
        series_id="test-series", key=FactKey("TEST-ENTITY-NOT-A-SECURITY", "op.ytd.v1",
        date(2024, 1, 1), date(2024, 6, 30), "ytd", "consolidated", "TEST-GAAP", "JPY"),
        revision=0, value=Decimal("100"), missing_reason=None,
        available_at=dt(7, 1), availability_basis="exact", recorded_at=dt(9, 1),
        representation="reported", extraction_method="structured", verification="source_tied",
        source_artifact_sha256="a"*64, source_locator="synthetic-test:row1",
        source_document_id="SYNTHETIC-NOT-A-FILING", synthetic=True)
    fields.update(changes)
    return Observation(**fields)


def selected(rows, when=None, **kwargs):
    return select_asof(rows, when or dt(7, 2), dt(12, 1),
                       allow_synthetic_for_tests=True, **kwargs)


class EvidenceTests(unittest.TestCase):
    def test_date_only_is_next_midnight(self):
        self.assertEqual(availability_bound(date(2024, 7, 1)), dt(7, 2, 0))
    def test_exact_time_and_latency(self):
        from datetime import time
        self.assertEqual(availability_bound(date(2024, 7, 1), time(15, 30), timedelta(minutes=2)),
                         datetime(2024, 7, 1, 15, 32, tzinfo=JST))
    def test_negative_latency_rejected(self):
        with self.assertRaises(ContractError): availability_bound(date(2024, 7, 1), latency=timedelta(seconds=-1))
    def test_synthetic_is_blocked_in_empirical_mode(self):
        result = select_asof([fixture()], dt(7, 2), dt(12, 1))
        self.assertFalse(result.observations)
        self.assertEqual(result.blocked[0][1], "synthetic_not_empirical")
    def test_reconstruction_is_not_replay(self):
        self.assertEqual(len(selected([fixture()]).observations), 1)
        self.assertFalse(selected([fixture()], mode="system_replay").observations)
    def test_equal_timestamp_not_yet_eligible(self):
        self.assertFalse(selected([fixture()], dt(7, 1)).observations)
    def test_future_revision_not_backdated(self):
        newer = fixture(record_id="SYNTHETIC-2", revision=1, value=Decimal("90"), available_at=dt(8, 1))
        self.assertEqual(selected([fixture(), newer]).observations[0].value, Decimal("100"))
        self.assertEqual(selected([fixture(), newer], dt(8, 2)).observations[0].value, Decimal("90"))
    def test_missing_correction_does_not_fall_back(self):
        newer = fixture(record_id="SYNTHETIC-2", revision=1, value=None,
            missing_reason="parse_failed", available_at=dt(7, 2))
        out = selected([fixture(), newer], dt(7, 3))
        self.assertFalse(out.observations)
        self.assertEqual(out.blocked[0][1], "parse_failed")
    def test_withdrawal_removes_value(self):
        newer = fixture(record_id="SYNTHETIC-2", revision=1, value=None,
            state="withdrawn", missing_reason="withdrawn", available_at=dt(7, 2))
        self.assertFalse(selected([fixture(), newer], dt(7, 3)).observations)
    def test_unknown_timing_blocks_lineage(self):
        newer = fixture(record_id="SYNTHETIC-2", revision=1, available_at=None, availability_basis="unknown")
        self.assertFalse(selected([fixture(), newer]).observations)
    def test_proxy_is_not_reported(self):
        out = selected([fixture(representation="proxy")])
        self.assertEqual(out.blocked[0][1], "representation_not_allowed")
    def test_guidance_requires_explicit_task_policy(self):
        row = fixture(representation="guidance")
        self.assertFalse(selected([row]).observations)
        self.assertTrue(selected([row], allowed_representations=frozenset({"guidance"})).observations)
    def test_llm_output_not_silently_direct(self):
        self.assertEqual(selected([fixture(extraction_method="llm")]).blocked[0][1], "extraction_method_not_allowed")
    def test_unverified_not_promoted(self):
        self.assertEqual(selected([fixture(verification="unverified")]).blocked[0][1], "unverified")
    def test_no_implicit_source_averaging(self):
        other = fixture(record_id="SYNTHETIC-2", source_id="other-test-provider", value=Decimal("80"))
        self.assertEqual(len(selected([fixture(), other]).observations), 2)
    def test_duplicate_record_rejected(self):
        with self.assertRaises(ContractError): selected([fixture(), fixture()])
    def test_ambiguous_revision_rejected(self):
        with self.assertRaises(ContractError): selected([fixture(), fixture(record_id="SYNTHETIC-2")])
    def test_dimensions_cannot_change_within_series(self):
        key = replace(fixture().key, scope="parent")
        with self.assertRaises(ContractError): selected([fixture(), fixture(record_id="SYNTHETIC-2", key=key)])
    def test_dimension_order_and_duplicates_rejected(self):
        with self.assertRaises(ContractError): replace(fixture().key, dimensions=(("z","a"),("a","b")))
        with self.assertRaises(ContractError): replace(fixture().key, dimensions=(("a","a"),("a","b")))
    def test_null_is_not_zero(self):
        with self.assertRaises(ContractError): fixture(value=None)
        self.assertTrue(selected([fixture(value=Decimal("0"))]).observations)
    def test_nan_and_float_rejected(self):
        for value in [Decimal("NaN"), Decimal("Infinity"), 100.0]:
            with self.assertRaises(ContractError): fixture(value=value)
    def test_timezone_required(self):
        with self.assertRaises(ContractError): fixture(available_at=datetime(2024, 7, 1))
    def test_sha_required(self):
        with self.assertRaises(ContractError): fixture(source_artifact_sha256="not-a-hash")
    def test_derived_requires_lineage(self):
        with self.assertRaises(ContractError): fixture(representation="derived")
    def test_frozen_snapshot_excludes_later_reparse(self):
        row = fixture(record_id="SYNTHETIC-2", value=Decimal("88"), recorded_at=dt(12, 2))
        self.assertEqual(selected([fixture(), row]).observations[0].value, Decimal("100"))
    def test_quarter_difference_preserves_lineage_and_timing(self):
        previous = fixture(record_id="SYNTHETIC-Q1", series_id="q1",
            key=replace(fixture().key, period_end=date(2024, 3, 31)),
            value=Decimal("40"), available_at=dt(5, 1))
        out = quarter_from_ytd(fixture(), previous, date(2024, 4, 1))
        self.assertEqual(out.value, Decimal("60"))
        self.assertEqual(out.available_at, dt(7, 1))
        self.assertEqual(out.input_ids, ("SYNTHETIC-1", "SYNTHETIC-Q1"))
        self.assertTrue(out.synthetic)
    def test_quarter_wrong_basis_rejected(self):
        prev = fixture(key=replace(fixture().key, period_end=date(2024, 3, 31), scope="parent"))
        with self.assertRaises(ContractError): quarter_from_ytd(fixture(), prev, date(2024, 4, 1))
    def test_quarter_gap_rejected(self):
        prev = fixture(key=replace(fixture().key, period_end=date(2024, 3, 30)))
        with self.assertRaises(ContractError): quarter_from_ytd(fixture(), prev, date(2024, 4, 1))
    def test_quarter_missing_rejected(self):
        prev = fixture(key=replace(fixture().key, period_end=date(2024, 3, 31)), value=None, missing_reason="not_reported")
        with self.assertRaises(ContractError): quarter_from_ytd(fixture(), prev, date(2024, 4, 1))
    def test_overlap_and_unmatured_labels_purged(self):
        rows = [Episode("safe",dt(1),dt(2),dt(3)),
                Episode("overlap",dt(1),dt(8),dt(9)),
                Episode("late_label",dt(1),dt(2),dt(9)),
                Episode("not_matured",dt(1),dt(2),None),
                Episode("touches_boundary",dt(1),dt(6),dt(7))]
        self.assertEqual(past_training_ids(rows, dt(7)), ("safe",))
    def test_negative_gap_rejected(self):
        with self.assertRaises(ContractError): past_training_ids([], dt(7), timedelta(days=-1))
    def test_impossible_label_time_rejected(self):
        with self.assertRaises(ContractError): Episode("bad",dt(1),dt(3),dt(2))
    def test_invalid_variance_fails_instead_of_zero_ci(self):
        for var in [-0.01, float("nan"), float("inf")]:
            with self.assertRaises(ContractError): checked_standard_error(var)
        self.assertEqual(checked_standard_error(4), 2)


if __name__ == "__main__":
    unittest.main()
