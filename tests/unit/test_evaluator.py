"""
Unit tests for the ComplianceEvaluator class and module-level evaluate_record function.

Tests all compliance status paths: COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE,
INSUFFICIENT_DATA. Also tests the lazy singleton pattern.

Validates: Requirements 6.1, 6.2, 9.4, 10.2, 17.3
"""

from unittest.mock import MagicMock, patch

import pytest

import src.evaluator as evaluator_module
from src.evaluator import ComplianceEvaluator, evaluate_record
from src.models import (
    CnameRecord,
    ComplianceStatus,
    EvaluationResult,
    MatchResult,
    ResourceType,
)


def _make_record(
    target: str = "mybucket.s3.amazonaws.com",
    record_name: str = "app.example.com",
    zone_id: str = "Z123",
    zone_name: str = "example.com",
    ttl: int = 300,
) -> CnameRecord:
    """Helper to build a CnameRecord with sensible defaults."""
    return CnameRecord(
        zone_id=zone_id,
        zone_name=zone_name,
        record_name=record_name,
        target=target,
        ttl=ttl,
    )


class TestComplianceEvaluatorNotApplicable:
    """Tests for the NOT_APPLICABLE path (non-AWS targets)."""

    def test_non_aws_target_returns_not_applicable(self):
        mock_matcher = MagicMock()
        mock_matcher.match.return_value = None
        mock_inventory = MagicMock()

        evaluator = ComplianceEvaluator(
            pattern_matcher=mock_matcher, inventory_query=mock_inventory
        )
        record = _make_record(target="www.example.com")
        result = evaluator.evaluate_record(record)

        assert result.compliance_status == ComplianceStatus.NOT_APPLICABLE
        assert result.resource_type is None
        assert result.resource_identifier is None
        assert "not an AWS resource endpoint" in result.annotation
        mock_inventory.resource_exists.assert_not_called()


class TestComplianceEvaluatorCompliant:
    """Tests for the COMPLIANT path (resource exists)."""

    def test_existing_s3_resource_returns_compliant(self):
        mock_matcher = MagicMock()
        mock_matcher.match.return_value = MatchResult(ResourceType.S3_BUCKET, "mybucket")
        mock_inventory = MagicMock()
        mock_inventory.resource_exists.return_value = True

        evaluator = ComplianceEvaluator(
            pattern_matcher=mock_matcher, inventory_query=mock_inventory
        )
        record = _make_record(target="mybucket.s3.amazonaws.com")
        result = evaluator.evaluate_record(record)

        assert result.compliance_status == ComplianceStatus.COMPLIANT
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.resource_identifier == "mybucket"
        assert "exists" in result.annotation

    def test_existing_cloudfront_resource_returns_compliant(self):
        mock_matcher = MagicMock()
        mock_matcher.match.return_value = MatchResult(
            ResourceType.CLOUDFRONT_DISTRIBUTION, "d1234abcd"
        )
        mock_inventory = MagicMock()
        mock_inventory.resource_exists.return_value = True

        evaluator = ComplianceEvaluator(
            pattern_matcher=mock_matcher, inventory_query=mock_inventory
        )
        record = _make_record(target="d1234abcd.cloudfront.net")
        result = evaluator.evaluate_record(record)

        assert result.compliance_status == ComplianceStatus.COMPLIANT
        assert result.resource_type == ResourceType.CLOUDFRONT_DISTRIBUTION
        assert result.resource_identifier == "d1234abcd"


class TestComplianceEvaluatorNonCompliant:
    """Tests for the NON_COMPLIANT path (dangling CNAME)."""

    def test_missing_s3_resource_returns_non_compliant(self):
        mock_matcher = MagicMock()
        mock_matcher.match.return_value = MatchResult(ResourceType.S3_BUCKET, "deleted-bucket")
        mock_inventory = MagicMock()
        mock_inventory.resource_exists.return_value = False

        evaluator = ComplianceEvaluator(
            pattern_matcher=mock_matcher, inventory_query=mock_inventory
        )
        record = _make_record(target="deleted-bucket.s3.amazonaws.com")
        result = evaluator.evaluate_record(record)

        assert result.compliance_status == ComplianceStatus.NON_COMPLIANT
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.resource_identifier == "deleted-bucket"
        assert "DANGLING CNAME DETECTED" in result.annotation
        assert "subdomain takeover" in result.annotation

    def test_non_compliant_annotation_contains_record_details(self):
        mock_matcher = MagicMock()
        mock_matcher.match.return_value = MatchResult(
            ResourceType.ELASTICBEANSTALK_ENVIRONMENT, "myenv"
        )
        mock_inventory = MagicMock()
        mock_inventory.resource_exists.return_value = False

        evaluator = ComplianceEvaluator(
            pattern_matcher=mock_matcher, inventory_query=mock_inventory
        )
        record = _make_record(
            target="myenv.elasticbeanstalk.com", record_name="app.example.com"
        )
        result = evaluator.evaluate_record(record)

        assert "app.example.com" in result.annotation
        assert "myenv.elasticbeanstalk.com" in result.annotation
        assert "myenv" in result.annotation


class TestComplianceEvaluatorInsufficientData:
    """Tests for the INSUFFICIENT_DATA path (inventory query failure)."""

    def test_inventory_failure_returns_insufficient_data(self):
        mock_matcher = MagicMock()
        mock_matcher.match.return_value = MatchResult(ResourceType.S3_BUCKET, "mybucket")
        mock_inventory = MagicMock()
        mock_inventory.resource_exists.return_value = None

        evaluator = ComplianceEvaluator(
            pattern_matcher=mock_matcher, inventory_query=mock_inventory
        )
        record = _make_record(target="mybucket.s3.amazonaws.com")
        result = evaluator.evaluate_record(record)

        assert result.compliance_status == ComplianceStatus.INSUFFICIENT_DATA
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.resource_identifier == "mybucket"
        assert "Unable to verify" in result.annotation


class TestComplianceEvaluatorBatch:
    """Tests for evaluate_records (batch evaluation)."""

    def test_evaluate_records_processes_all_records(self):
        mock_matcher = MagicMock()
        mock_matcher.match.return_value = None
        mock_inventory = MagicMock()

        evaluator = ComplianceEvaluator(
            pattern_matcher=mock_matcher, inventory_query=mock_inventory
        )
        records = [_make_record(target="a.example.com"), _make_record(target="b.example.com")]
        results = evaluator.evaluate_records(records)

        assert len(results) == 2
        assert all(r.compliance_status == ComplianceStatus.NOT_APPLICABLE for r in results)


class TestModuleLevelEvaluateRecord:
    """Tests for the lazy singleton module-level evaluate_record function."""

    def teardown_method(self):
        # Reset the module-level singleton after each test
        evaluator_module._evaluator = None

    def test_singleton_is_lazily_initialized(self):
        """The module-level _evaluator starts as None."""
        evaluator_module._evaluator = None
        assert evaluator_module._evaluator is None

    @patch.object(ComplianceEvaluator, "evaluate_record")
    @patch("src.evaluator.ComplianceEvaluator", wraps=ComplianceEvaluator)
    def test_singleton_created_on_first_call(self, mock_cls, mock_eval):
        evaluator_module._evaluator = None
        mock_eval.return_value = MagicMock(spec=EvaluationResult)

        record = _make_record(target="www.example.com")
        evaluate_record(record)

        # ComplianceEvaluator was instantiated
        mock_cls.assert_called_once()

    @patch("src.evaluator.ComplianceEvaluator", wraps=ComplianceEvaluator)
    def test_singleton_reused_on_subsequent_calls(self, mock_cls):
        evaluator_module._evaluator = None

        record = _make_record(target="www.example.com")
        evaluate_record(record)
        evaluate_record(record)

        # Only one instance created despite two calls
        mock_cls.assert_called_once()

    def test_singleton_returns_valid_result(self):
        evaluator_module._evaluator = None

        record = _make_record(target="www.example.com")
        result = evaluate_record(record)

        assert isinstance(result, EvaluationResult)
        assert result.compliance_status == ComplianceStatus.NOT_APPLICABLE
