"""Integration tests for MetricsPublisher using moto-mocked CloudWatch.

Tests metric publishing against a realistic moto-backed CloudWatch environment.

Validates: Requirements 19.4
"""

from datetime import datetime, timezone

import boto3
import pytest
from moto import mock_aws

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


@pytest.mark.integration
@mock_aws
class TestMetricsPublisherIntegration:
    """Integration tests for MetricsPublisher with moto CloudWatch."""

    def test_publish_evaluation_metrics_succeeds(self):
        """Evaluation metrics are published successfully to CloudWatch."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        results = [
            _make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET),
            _make_result(ComplianceStatus.NON_COMPLIANT, ResourceType.S3_BUCKET),
            _make_result(ComplianceStatus.NOT_APPLICABLE, None),
        ]

        success = publisher.publish_evaluation_metrics(results)
        assert success is True

    def test_metrics_appear_in_cloudwatch(self):
        """Published metrics are retrievable from CloudWatch."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        results = [_make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET)]
        publisher.publish_evaluation_metrics(results)

        # Verify metrics exist in the namespace
        resp = cw.list_metrics(Namespace=MetricsPublisher.NAMESPACE)
        metric_names = {m["MetricName"] for m in resp["Metrics"]}

        assert "TotalEvaluated" in metric_names
        assert "Compliant" in metric_names

    def test_resource_type_dimensions_published(self):
        """Metrics with ResourceType dimensions are published."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        results = [_make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET)]
        publisher.publish_evaluation_metrics(results)

        resp = cw.list_metrics(Namespace=MetricsPublisher.NAMESPACE)
        dimensioned = [
            m for m in resp["Metrics"]
            if any(d["Name"] == "ResourceType" for d in m.get("Dimensions", []))
        ]
        assert len(dimensioned) > 0

    def test_publish_execution_metrics_succeeds(self):
        """Execution metrics are published successfully."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        success = publisher.publish_execution_metrics(
            duration_ms=1500.0,
            zones_scanned=5,
            records_found=42,
            errors=0,
        )
        assert success is True

    def test_execution_metrics_appear_in_cloudwatch(self):
        """Execution metrics are retrievable from CloudWatch."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        publisher.publish_execution_metrics(
            duration_ms=1500.0,
            zones_scanned=5,
            records_found=42,
            errors=1,
        )

        resp = cw.list_metrics(Namespace=MetricsPublisher.NAMESPACE)
        metric_names = {m["MetricName"] for m in resp["Metrics"]}

        assert "ExecutionDuration" in metric_names
        assert "ZonesScanned" in metric_names
        assert "RecordsFound" in metric_names
        assert "Errors" in metric_names

    def test_custom_timestamp_used(self):
        """Evaluation metrics use the provided timestamp."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        ts = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        results = [_make_result(ComplianceStatus.COMPLIANT)]

        success = publisher.publish_evaluation_metrics(results, evaluation_timestamp=ts)
        assert success is True

    def test_empty_results_publishes_zero_counts(self):
        """Empty results still publish aggregate metrics with zero values."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        success = publisher.publish_evaluation_metrics([])
        assert success is True

        resp = cw.list_metrics(Namespace=MetricsPublisher.NAMESPACE)
        metric_names = {m["MetricName"] for m in resp["Metrics"]}
        assert "TotalEvaluated" in metric_names

    def test_mixed_statuses_all_published(self):
        """All compliance status metrics are published for mixed results."""
        cw = boto3.client("cloudwatch", region_name="us-east-1")
        publisher = MetricsPublisher(client=cw)

        results = [
            _make_result(ComplianceStatus.COMPLIANT, ResourceType.S3_BUCKET),
            _make_result(ComplianceStatus.NON_COMPLIANT, ResourceType.CLOUDFRONT_DISTRIBUTION),
            _make_result(ComplianceStatus.NOT_APPLICABLE, None),
            _make_result(ComplianceStatus.INSUFFICIENT_DATA, None),
        ]

        success = publisher.publish_evaluation_metrics(results)
        assert success is True

        resp = cw.list_metrics(Namespace=MetricsPublisher.NAMESPACE)
        metric_names = {m["MetricName"] for m in resp["Metrics"]}

        assert "TotalEvaluated" in metric_names
        assert "Compliant" in metric_names
        assert "NonCompliant" in metric_names
        assert "NotApplicable" in metric_names
        assert "InsufficientData" in metric_names
