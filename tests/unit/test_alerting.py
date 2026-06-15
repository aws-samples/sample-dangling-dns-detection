"""
Unit tests for AlertingService.

Tests finding creation, SNS publishing, timestamp consistency,
and process_results flow.

Validates: Requirements 3.2, 4.1, 4.2, 11.1, 13.1, 13.2, 17.5
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

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


def _make_alerting_service(sns_topic_arn: str | None = "arn:aws:sns:us-east-1:123456789012:test-topic") -> AlertingService:
    """Create an AlertingService with mocked AWS clients."""
    mock_sh = MagicMock()
    mock_sh.meta.region_name = "us-east-1"
    mock_sh.batch_import_findings.return_value = {
        "FailedCount": 0,
        "SuccessCount": 1,
    }

    mock_sns = MagicMock()
    mock_sns.publish.return_value = {"MessageId": "msg-123"}

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

    return AlertingService(
        securityhub_client=mock_sh,
        sns_client=mock_sns,
        sts_client=mock_sts,
        sns_topic_arn=sns_topic_arn,
    )


# ---------------------------------------------------------------------------
# Finding creation
# ---------------------------------------------------------------------------

class TestFindingCreation:
    """Tests for create_security_hub_finding."""

    def test_creates_finding_for_non_compliant_result(self):
        svc = _make_alerting_service()
        result = _make_non_compliant_result()
        finding_id = svc.create_security_hub_finding(result)

        assert finding_id is not None
        svc._securityhub.batch_import_findings.assert_called_once()
        finding = svc._securityhub.batch_import_findings.call_args[1]["Findings"][0]
        assert finding["Severity"]["Label"] == "HIGH"
        assert result.record.record_name in finding["Title"]

    def test_returns_none_when_resource_type_is_none(self):
        svc = _make_alerting_service()
        result = EvaluationResult(
            record=_make_record(),
            resource_type=None,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            annotation="test",
        )
        assert svc.create_security_hub_finding(result) is None
        svc._securityhub.batch_import_findings.assert_not_called()

    def test_returns_none_on_client_error(self):
        svc = _make_alerting_service()
        svc._securityhub.batch_import_findings.side_effect = ClientError(
            {"Error": {"Code": "InternalException", "Message": "boom"}},
            "BatchImportFindings",
        )
        result = _make_non_compliant_result()
        assert svc.create_security_hub_finding(result) is None

    def test_handles_invalid_access_exception(self):
        svc = _make_alerting_service()
        svc._securityhub.batch_import_findings.side_effect = ClientError(
            {"Error": {"Code": "InvalidAccessException", "Message": "not enabled"}},
            "BatchImportFindings",
        )
        result = _make_non_compliant_result()
        assert svc.create_security_hub_finding(result) is None

    def test_uses_provided_timestamp(self):
        svc = _make_alerting_service()
        result = _make_non_compliant_result()
        ts = "2024-01-15T10:30:00+00:00"
        svc.create_security_hub_finding(result, timestamp=ts)

        finding = svc._securityhub.batch_import_findings.call_args[1]["Findings"][0]
        assert finding["CreatedAt"] == ts
        assert finding["UpdatedAt"] == ts


# ---------------------------------------------------------------------------
# SNS publishing
# ---------------------------------------------------------------------------

class TestSnsPublishing:
    """Tests for publish_sns_notification."""

    def test_publishes_notification_successfully(self):
        svc = _make_alerting_service()
        result = _make_non_compliant_result()
        assert svc.publish_sns_notification(result) is True
        svc._sns.publish.assert_called_once()

    def test_returns_false_when_no_topic_arn(self):
        svc = _make_alerting_service(sns_topic_arn=None)
        result = _make_non_compliant_result()
        assert svc.publish_sns_notification(result) is False
        svc._sns.publish.assert_not_called()

    def test_returns_false_when_resource_type_is_none(self):
        svc = _make_alerting_service()
        result = EvaluationResult(
            record=_make_record(),
            resource_type=None,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            annotation="test",
        )
        assert svc.publish_sns_notification(result) is False

    def test_returns_false_on_client_error(self):
        svc = _make_alerting_service()
        svc._sns.publish.side_effect = ClientError(
            {"Error": {"Code": "NotFoundException", "Message": "topic gone"}},
            "Publish",
        )
        result = _make_non_compliant_result()
        assert svc.publish_sns_notification(result) is False

    def test_subject_truncated_to_100_chars(self):
        svc = _make_alerting_service()
        long_name = "a" * 200
        record = _make_record(record_name=long_name)
        result = _make_non_compliant_result(record=record)
        svc.publish_sns_notification(result)

        call_kwargs = svc._sns.publish.call_args[1]
        assert len(call_kwargs["Subject"]) <= 100

    def test_sns_message_contains_expected_fields(self):
        svc = _make_alerting_service()
        result = _make_non_compliant_result()
        svc.publish_sns_notification(result)

        call_kwargs = svc._sns.publish.call_args[1]
        msg = json.loads(call_kwargs["Message"])
        assert msg["alertType"] == "DanglingCNAME"
        assert msg["severity"] == "HIGH"
        assert msg["record"]["name"] == result.record.record_name
        assert msg["resource"]["type"] == "S3"
        assert "timestamp" in msg

    def test_uses_provided_timestamp_in_message(self):
        svc = _make_alerting_service()
        result = _make_non_compliant_result()
        ts = "2024-01-15T10:30:00+00:00"
        svc.publish_sns_notification(result, timestamp=ts)

        call_kwargs = svc._sns.publish.call_args[1]
        msg = json.loads(call_kwargs["Message"])
        assert msg["timestamp"] == ts


# ---------------------------------------------------------------------------
# Timestamp consistency
# ---------------------------------------------------------------------------

class TestTimestampConsistency:
    """Tests that process_results uses a single timestamp across all alerts."""

    def test_single_timestamp_across_finding_and_notification(self):
        svc = _make_alerting_service()
        result = _make_non_compliant_result()
        svc.process_results([result])

        # Extract timestamps from both calls
        finding = svc._securityhub.batch_import_findings.call_args[1]["Findings"][0]
        sns_msg = json.loads(svc._sns.publish.call_args[1]["Message"])

        assert finding["CreatedAt"] == sns_msg["timestamp"]
        assert finding["UpdatedAt"] == sns_msg["timestamp"]

    def test_same_timestamp_for_multiple_results(self):
        svc = _make_alerting_service()
        results = [
            _make_non_compliant_result(
                record=_make_record(record_name=f"app{i}.example.com"),
            )
            for i in range(3)
        ]
        svc.process_results(results)

        # All findings should share the same timestamp
        calls = svc._securityhub.batch_import_findings.call_args_list
        timestamps = {
            call[1]["Findings"][0]["CreatedAt"] for call in calls
        }
        assert len(timestamps) == 1, "All findings should share the same timestamp"

        # All SNS messages should share the same timestamp
        sns_calls = svc._sns.publish.call_args_list
        sns_timestamps = set()
        for call in sns_calls:
            msg = json.loads(call[1]["Message"])
            sns_timestamps.add(msg["timestamp"])
        assert len(sns_timestamps) == 1, "All SNS messages should share the same timestamp"

        # Finding and SNS timestamps should match
        assert timestamps == sns_timestamps


# ---------------------------------------------------------------------------
# process_results flow
# ---------------------------------------------------------------------------

class TestProcessResults:
    """Tests for the process_results orchestration method."""

    def test_skips_compliant_results(self):
        svc = _make_alerting_service()
        compliant = EvaluationResult(
            record=_make_record(),
            resource_type=None,
            compliance_status=ComplianceStatus.COMPLIANT,
            annotation="ok",
        )
        summary = svc.process_results([compliant])
        assert summary["findings_created"] == 0
        assert summary["notifications_sent"] == 0
        svc._securityhub.batch_import_findings.assert_not_called()
        svc._sns.publish.assert_not_called()

    def test_counts_successful_findings_and_notifications(self):
        svc = _make_alerting_service()
        result = _make_non_compliant_result()
        summary = svc.process_results([result])
        assert summary["findings_created"] == 1
        assert summary["notifications_sent"] == 1
        assert summary["findings_failed"] == 0
        assert summary["notifications_failed"] == 0

    def test_counts_failed_findings(self):
        svc = _make_alerting_service()
        svc._securityhub.batch_import_findings.side_effect = ClientError(
            {"Error": {"Code": "InternalException", "Message": "boom"}},
            "BatchImportFindings",
        )
        result = _make_non_compliant_result()
        summary = svc.process_results([result])
        assert summary["findings_created"] == 0
        assert summary["findings_failed"] == 1

    def test_counts_failed_notifications(self):
        svc = _make_alerting_service()
        svc._sns.publish.side_effect = ClientError(
            {"Error": {"Code": "NotFoundException", "Message": "gone"}},
            "Publish",
        )
        result = _make_non_compliant_result()
        summary = svc.process_results([result])
        assert summary["notifications_sent"] == 0
        assert summary["notifications_failed"] == 1

    def test_no_sns_when_topic_not_configured(self):
        svc = _make_alerting_service(sns_topic_arn=None)
        result = _make_non_compliant_result()
        summary = svc.process_results([result])
        assert summary["notifications_sent"] == 0
        assert summary["notifications_failed"] == 0
        svc._sns.publish.assert_not_called()

    def test_empty_results_returns_zero_counts(self):
        svc = _make_alerting_service()
        summary = svc.process_results([])
        assert summary == {
            "findings_created": 0,
            "findings_failed": 0,
            "notifications_sent": 0,
            "notifications_failed": 0,
        }

    def test_mixed_compliance_statuses(self):
        svc = _make_alerting_service()
        results = [
            _make_non_compliant_result(),
            EvaluationResult(
                record=_make_record(record_name="ok.example.com"),
                resource_type=None,
                compliance_status=ComplianceStatus.COMPLIANT,
                annotation="ok",
            ),
            EvaluationResult(
                record=_make_record(record_name="na.example.com"),
                resource_type=None,
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                annotation="n/a",
            ),
        ]
        summary = svc.process_results(results)
        assert summary["findings_created"] == 1
        assert summary["notifications_sent"] == 1


# ---------------------------------------------------------------------------
# Archive finding
# ---------------------------------------------------------------------------

class TestArchiveFinding:
    """Tests for archive_security_hub_finding."""

    def test_archives_finding_successfully(self):
        svc = _make_alerting_service()
        assert svc.archive_security_hub_finding("finding-123") is True
        svc._securityhub.batch_update_findings.assert_called_once()

    def test_returns_false_on_client_error(self):
        svc = _make_alerting_service()
        svc._securityhub.batch_update_findings.side_effect = ClientError(
            {"Error": {"Code": "InternalException", "Message": "boom"}},
            "BatchUpdateFindings",
        )
        assert svc.archive_security_hub_finding("finding-123") is False


# ---------------------------------------------------------------------------
# __all__ export list
# ---------------------------------------------------------------------------

class TestAllExport:
    """Tests for __all__ export list."""

    def test_all_contains_alerting_service(self):
        import src.alerting as mod
        assert hasattr(mod, "__all__")
        assert "AlertingService" in mod.__all__
