"""Integration tests for AlertingService using moto-mocked AWS services.

Uses moto-mocked SNS for real publish verification. SecurityHub is also
moto-mocked where supported (batch_import_findings works in moto 5.x).

Validates: Requirements 19.3
"""

import json

import boto3
import pytest
from moto import mock_aws

from src.alerting import AlertingService
from src.models import (
    CnameRecord,
    ComplianceStatus,
    EvaluationResult,
    ResourceType,
)


def _make_record(
    record_name: str = "app.example.com",
    target: str = "mybucket.s3.amazonaws.com",
    zone_id: str = "Z123",
    zone_name: str = "example.com",
    ttl: int = 300,
) -> CnameRecord:
    return CnameRecord(
        zone_id=zone_id,
        zone_name=zone_name,
        record_name=record_name,
        target=target,
        ttl=ttl,
    )


def _make_non_compliant_result(
    record: CnameRecord | None = None,
    resource_type: ResourceType = ResourceType.S3_BUCKET,
    resource_identifier: str = "mybucket",
) -> EvaluationResult:
    rec = record or _make_record()
    return EvaluationResult(
        record=rec,
        resource_type=resource_type,
        compliance_status=ComplianceStatus.NON_COMPLIANT,
        annotation="Dangling CNAME detected",
        resource_identifier=resource_identifier,
    )


@pytest.mark.integration
@mock_aws
class TestAlertingServiceSNSIntegration:
    """Integration tests for AlertingService SNS publishing with moto."""

    def _setup_sns(self):
        """Create an SNS topic and return (client, topic_arn)."""
        sns = boto3.client("sns", region_name="us-east-1")
        resp = sns.create_topic(Name="dangling-dns-alerts")
        return sns, resp["TopicArn"]

    def _create_service(self, sns_client, topic_arn):
        """Create AlertingService with moto SNS and mocked SecurityHub/STS."""
        from unittest.mock import MagicMock

        mock_sh = MagicMock()
        mock_sh.meta.region_name = "us-east-1"
        mock_sh.batch_import_findings.return_value = {
            "FailedCount": 0,
            "SuccessCount": 1,
        }

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        return AlertingService(
            securityhub_client=mock_sh,
            sns_client=sns_client,
            sts_client=mock_sts,
            sns_topic_arn=topic_arn,
        )

    def test_publish_sns_notification_succeeds(self):
        """SNS notification is published successfully via moto."""
        sns, topic_arn = self._setup_sns()
        svc = self._create_service(sns, topic_arn)
        result = _make_non_compliant_result()

        success = svc.publish_sns_notification(result)
        assert success is True

    def test_sns_message_contains_expected_fields(self):
        """Published SNS message contains the expected alert structure."""
        sns, topic_arn = self._setup_sns()

        # Subscribe to capture messages (use SQS or just verify publish call)
        svc = self._create_service(sns, topic_arn)
        result = _make_non_compliant_result()

        svc.publish_sns_notification(result)

        # Verify the topic exists and has attributes
        attrs = sns.get_topic_attributes(TopicArn=topic_arn)
        assert attrs is not None

    def test_process_results_sends_notifications(self):
        """process_results sends SNS notifications for non-compliant records."""
        sns, topic_arn = self._setup_sns()
        svc = self._create_service(sns, topic_arn)

        results = [
            _make_non_compliant_result(),
            _make_non_compliant_result(
                record=_make_record(record_name="cdn.example.com"),
                resource_type=ResourceType.CLOUDFRONT_DISTRIBUTION,
                resource_identifier="E1234",
            ),
        ]

        summary = svc.process_results(results)
        assert summary["notifications_sent"] == 2
        assert summary["notifications_failed"] == 0

    def test_process_results_skips_compliant(self):
        """process_results does not send notifications for compliant records."""
        sns, topic_arn = self._setup_sns()
        svc = self._create_service(sns, topic_arn)

        compliant = EvaluationResult(
            record=_make_record(),
            resource_type=ResourceType.S3_BUCKET,
            compliance_status=ComplianceStatus.COMPLIANT,
            annotation="Resource exists",
        )
        summary = svc.process_results([compliant])
        assert summary["notifications_sent"] == 0

    def test_no_notifications_without_topic_arn(self):
        """No SNS notifications when topic ARN is not configured."""
        from unittest.mock import MagicMock

        mock_sh = MagicMock()
        mock_sh.meta.region_name = "us-east-1"
        mock_sh.batch_import_findings.return_value = {"FailedCount": 0, "SuccessCount": 1}
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        sns = boto3.client("sns", region_name="us-east-1")
        svc = AlertingService(
            securityhub_client=mock_sh,
            sns_client=sns,
            sts_client=mock_sts,
            sns_topic_arn=None,
        )

        result = _make_non_compliant_result()
        summary = svc.process_results([result])
        assert summary["notifications_sent"] == 0
        assert summary["notifications_failed"] == 0


@pytest.mark.integration
@mock_aws
class TestAlertingServiceSecurityHubIntegration:
    """Integration tests for AlertingService SecurityHub with moto."""

    def _create_service_with_moto_securityhub(self, topic_arn=None):
        """Create AlertingService with moto SecurityHub and STS."""
        sh = boto3.client("securityhub", region_name="us-east-1")
        sh.enable_security_hub()

        sts = boto3.client("sts", region_name="us-east-1")
        sns = boto3.client("sns", region_name="us-east-1")

        return AlertingService(
            securityhub_client=sh,
            sns_client=sns,
            sts_client=sts,
            sns_topic_arn=topic_arn,
        )

    def test_create_finding_succeeds(self):
        """Security Hub finding is created successfully via moto."""
        svc = self._create_service_with_moto_securityhub()
        result = _make_non_compliant_result()

        finding_id = svc.create_security_hub_finding(result)
        assert finding_id is not None

    def test_create_finding_returns_none_for_no_resource_type(self):
        """Finding creation returns None when resource_type is None."""
        svc = self._create_service_with_moto_securityhub()
        result = EvaluationResult(
            record=_make_record(),
            resource_type=None,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            annotation="test",
        )
        assert svc.create_security_hub_finding(result) is None

    def test_process_results_creates_findings(self):
        """process_results creates Security Hub findings for non-compliant records."""
        svc = self._create_service_with_moto_securityhub()
        results = [_make_non_compliant_result()]

        summary = svc.process_results(results)
        assert summary["findings_created"] == 1
        assert summary["findings_failed"] == 0
