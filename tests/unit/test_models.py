"""
Unit tests for data models in src/models.py.

Tests frozen behavior, slots presence, validation errors, and MatchResult.

Validates: Requirements 9.1, 9.2, 10.1, 12.1, 12.2, 14.1-14.5, 23.1, 23.2
"""

import dataclasses
import pytest

from src.models import (
    CnameRecord,
    ComplianceStatus,
    EvaluationResult,
    MatchResult,
    ResourceType,
)


class TestCnameRecordFrozen:
    """Test that CnameRecord is frozen (immutable)."""

    def _make_record(self) -> CnameRecord:
        return CnameRecord(
            zone_id="Z123",
            zone_name="example.com",
            record_name="app.example.com",
            target="mybucket.s3.amazonaws.com",
            ttl=300,
        )

    def test_cannot_mutate_zone_id(self):
        record = self._make_record()
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.zone_id = "Z999"  # type: ignore[misc]

    def test_cannot_mutate_ttl(self):
        record = self._make_record()
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.ttl = 600  # type: ignore[misc]

    def test_cannot_mutate_target(self):
        record = self._make_record()
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.target = "other.s3.amazonaws.com"  # type: ignore[misc]


class TestCnameRecordSlots:
    """Test that CnameRecord uses __slots__."""

    def test_has_slots(self):
        assert hasattr(CnameRecord, "__slots__")

    def test_no_dict(self):
        record = CnameRecord(
            zone_id="Z123",
            zone_name="example.com",
            record_name="app.example.com",
            target="mybucket.s3.amazonaws.com",
            ttl=300,
        )
        assert not hasattr(record, "__dict__")


class TestCnameRecordValidation:
    """Test __post_init__ validation on CnameRecord."""

    def test_valid_construction(self):
        record = CnameRecord(
            zone_id="Z123",
            zone_name="example.com",
            record_name="app.example.com",
            target="mybucket.s3.amazonaws.com",
            ttl=0,
        )
        assert record.zone_id == "Z123"
        assert record.ttl == 0

    def test_empty_zone_id_raises(self):
        with pytest.raises(ValueError, match="zone_id"):
            CnameRecord(
                zone_id="",
                zone_name="example.com",
                record_name="app.example.com",
                target="mybucket.s3.amazonaws.com",
                ttl=300,
            )

    def test_empty_record_name_raises(self):
        with pytest.raises(ValueError, match="record_name"):
            CnameRecord(
                zone_id="Z123",
                zone_name="example.com",
                record_name="",
                target="mybucket.s3.amazonaws.com",
                ttl=300,
            )

    def test_empty_target_raises(self):
        with pytest.raises(ValueError, match="target"):
            CnameRecord(
                zone_id="Z123",
                zone_name="example.com",
                record_name="app.example.com",
                target="",
                ttl=300,
            )

    def test_negative_ttl_raises(self):
        with pytest.raises(ValueError, match="ttl"):
            CnameRecord(
                zone_id="Z123",
                zone_name="example.com",
                record_name="app.example.com",
                target="mybucket.s3.amazonaws.com",
                ttl=-1,
            )

    def test_non_integer_ttl_raises(self):
        with pytest.raises(ValueError, match="ttl"):
            CnameRecord(
                zone_id="Z123",
                zone_name="example.com",
                record_name="app.example.com",
                target="mybucket.s3.amazonaws.com",
                ttl=3.14,  # type: ignore[arg-type]
            )

    def test_boolean_ttl_raises(self):
        with pytest.raises(ValueError, match="ttl"):
            CnameRecord(
                zone_id="Z123",
                zone_name="example.com",
                record_name="app.example.com",
                target="mybucket.s3.amazonaws.com",
                ttl=True,  # type: ignore[arg-type]
            )


class TestEvaluationResultFrozenSlots:
    """Test that EvaluationResult is frozen and uses slots."""

    def _make_result(self) -> EvaluationResult:
        record = CnameRecord(
            zone_id="Z123",
            zone_name="example.com",
            record_name="app.example.com",
            target="mybucket.s3.amazonaws.com",
            ttl=300,
        )
        return EvaluationResult(
            record=record,
            resource_type=ResourceType.S3_BUCKET,
            compliance_status=ComplianceStatus.COMPLIANT,
            annotation="Resource exists",
        )

    def test_frozen(self):
        result = self._make_result()
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.annotation = "changed"  # type: ignore[misc]

    def test_has_slots(self):
        assert hasattr(EvaluationResult, "__slots__")

    def test_no_dict(self):
        result = self._make_result()
        assert not hasattr(result, "__dict__")


class TestMatchResult:
    """Test MatchResult NamedTuple."""

    def test_construction(self):
        mr = MatchResult(resource_type=ResourceType.S3_BUCKET, identifier="mybucket")
        assert mr.resource_type == ResourceType.S3_BUCKET
        assert mr.identifier == "mybucket"

    def test_tuple_unpacking(self):
        mr = MatchResult(resource_type=ResourceType.CLOUDFRONT_DISTRIBUTION, identifier="d123")
        rt, ident = mr
        assert rt == ResourceType.CLOUDFRONT_DISTRIBUTION
        assert ident == "d123"

    def test_indexing(self):
        mr = MatchResult(resource_type=ResourceType.S3_BUCKET, identifier="bucket")
        assert mr[0] == ResourceType.S3_BUCKET
        assert mr[1] == "bucket"
