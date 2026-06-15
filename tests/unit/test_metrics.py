"""Unit tests for MetricsPublisher.

Tests metric data construction, Counter usage, and timestamp parameter.
Validates: Requirements 17.6, 22.1, 22.2, 11.2
"""

from collections import Counter
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.metrics import MetricsPublisher
from src.models import (
    CnameRecord,
    ComplianceStatus,
    EvaluationResult,
    ResourceType,
)


def _make_record(
    zone_id: str = "Z123",
    record_name: str = "app.example.com",
    target: str = "mybucket.s3.amazonaws.com",
) -> CnameRecord:
    return CnameRecord(
        zone_id=zone_id,
        zone_name="example.com",
        record_name=record_name,
        target=target,
        ttl=300,
    )


def _make_result(
    status: ComplianceStatus = ComplianceStatus.COMPLIANT,
    resource_type: ResourceType | None = ResourceType.S3_BUCKET,
) -> EvaluationResult:
    return EvaluationResult(
        record=_make_record(),
        resource_type=resource_type,
        compliance_status=status,
        annotation="test annotation",
    )


class TestCalculateMetrics:
    """Tests for _calculate_metrics using Counter."""

    def test_empty_results(self):
        publisher = MetricsPublisher(client=MagicMock())
        metrics = publisher._calculate_metrics([])
        assert metrics["total"] == 0
        assert isinstance(metrics["by_status"], Counter)
        assert sum(metrics["by_status"].values()) == 0

    def test_single_compliant_result(self):
        publisher = MetricsPublisher(client=MagicMock())
        results = [_make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET)]
        metrics = publisher._calculate_metrics(results)
        assert metrics["total"] == 1
        assert metrics["by_status"][ComplianceStatus.COMPLIANT] == 1

    def test_mixed_statuses(self):
        publisher = MetricsPublisher(client=MagicMock())
        results = [
            _make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET),
            _make_result(ComplianceStatus.NON_COMPLIANT, ResourceType.S3_BUCKET),
            _make_result(ComplianceStatus.NOT_APPLICABLE, None),
            _make_result(ComplianceStatus.INSUFFICIENT_DATA, None),
        ]
        metrics = publisher._calculate_metrics(results)
        assert metrics["total"] == 4
        assert metrics["by_status"][ComplianceStatus.COMPLIANT] == 1
        assert metrics["by_status"][ComplianceStatus.NON_COMPLIANT] == 1
        assert metrics["by_status"][ComplianceStatus.NOT_APPLICABLE] == 1
        assert metrics["by_status"][ComplianceStatus.INSUFFICIENT_DATA] == 1

    def test_by_resource_type_only_counts_typed_results(self):
        publisher = MetricsPublisher(client=MagicMock())
        results = [
            _make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET),
            _make_result(ComplianceStatus.NOT_APPLICABLE, None),
        ]
        metrics = publisher._calculate_metrics(results)
        assert ResourceType.S3_BUCKET in metrics["by_resource_type"]
        assert metrics["by_resource_type"][ResourceType.S3_BUCKET][ComplianceStatus.COMPLIANT] == 1
        # None resource_type should not appear in by_resource_type
        assert None not in metrics["by_resource_type"]

    def test_counter_type_used(self):
        """Verify Counter is used for by_status (Requirement 22.1)."""
        publisher = MetricsPublisher(client=MagicMock())
        results = [_make_result(ComplianceStatus.COMPLIANT)]
        metrics = publisher._calculate_metrics(results)
        assert isinstance(metrics["by_status"], Counter)


class TestBuildMetricData:
    """Tests for _build_metric_data construction."""

    def test_always_includes_aggregate_metrics(self):
        publisher = MetricsPublisher(client=MagicMock())
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        metrics = publisher._calculate_metrics([])
        data = publisher._build_metric_data(metrics, ts)
        names = [d["MetricName"] for d in data]
        # Should always have TotalEvaluated + 4 status metrics
        assert "TotalEvaluated" in names
        assert "Compliant" in names
        assert "NonCompliant" in names
        assert "NotApplicable" in names
        assert "InsufficientData" in names
        # All timestamps should match
        for d in data:
            assert d["Timestamp"] == ts

    def test_resource_type_dimensions_present(self):
        publisher = MetricsPublisher(client=MagicMock())
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        results = [_make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET)]
        metrics = publisher._calculate_metrics(results)
        data = publisher._build_metric_data(metrics, ts)
        dimensioned = [d for d in data if "Dimensions" in d]
        assert len(dimensioned) > 0
        assert dimensioned[0]["Dimensions"][0]["Value"] == "S3"


class TestPublishEvaluationMetrics:
    """Tests for publish_evaluation_metrics including timestamp parameter."""

    def test_uses_provided_timestamp(self):
        mock_client = MagicMock()
        publisher = MetricsPublisher(client=mock_client)
        ts = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        results = [_make_result(ComplianceStatus.COMPLIANT)]

        publisher.publish_evaluation_metrics(results, evaluation_timestamp=ts)

        call_args = mock_client.put_metric_data.call_args
        metric_data = call_args.kwargs["MetricData"]
        for md in metric_data:
            assert md["Timestamp"] == ts

    def test_falls_back_to_utc_now_when_no_timestamp(self):
        mock_client = MagicMock()
        publisher = MetricsPublisher(client=mock_client)
        results = [_make_result(ComplianceStatus.COMPLIANT)]

        publisher.publish_evaluation_metrics(results)

        call_args = mock_client.put_metric_data.call_args
        metric_data = call_args.kwargs["MetricData"]
        # All timestamps should be timezone-aware UTC
        for md in metric_data:
            assert md["Timestamp"].tzinfo is not None

    def test_returns_true_on_success(self):
        mock_client = MagicMock()
        publisher = MetricsPublisher(client=mock_client)
        assert publisher.publish_evaluation_metrics([_make_result()]) is True

    def test_returns_true_for_empty_results(self):
        mock_client = MagicMock()
        publisher = MetricsPublisher(client=mock_client)
        # Even empty results produce aggregate metrics, so still True
        assert publisher.publish_evaluation_metrics([]) is True
