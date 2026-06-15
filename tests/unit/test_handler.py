"""
Unit tests for ConfigRuleHandler.

Tests retry logic with deterministic seed, error isolation,
lazy initialization, and summary calculation.

Validates: Requirements 2.1, 2.2, 2.3, 7.1, 7.2, 7.3, 8.1, 8.2,
           13.1, 13.2, 17.4, 24.1, 25.1, 25.2
"""

import random
from collections import Counter
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from src.handler import ConfigRuleHandler, _MAX_ANNOTATION_LENGTH
from src.models import (
    CnameRecord,
    ComplianceStatus,
    EvaluationResult,
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


def _make_result(
    status: ComplianceStatus = ComplianceStatus.COMPLIANT,
    record: CnameRecord | None = None,
) -> EvaluationResult:
    rec = record or _make_record()
    return EvaluationResult(
        record=rec,
        resource_type=None,
        compliance_status=status,
        annotation="test",
    )


def _make_client_error(code: str = "ThrottlingException") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "err"}},
        "operation",
    )


class TestLazyInitialization:
    """Task 8.1: AlertingService and MetricsPublisher are lazily initialized."""

    def test_alerting_not_created_in_init(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        # The private backing field should be None after __init__
        assert handler._ConfigRuleHandler__alerting is None

    def test_metrics_not_created_in_init(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        assert handler._ConfigRuleHandler__metrics is None

    def test_alerting_created_on_first_access(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        svc = handler._alerting_service
        assert svc is not None
        assert handler._ConfigRuleHandler__alerting is svc

    def test_metrics_created_on_first_access(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        pub = handler._metrics_publisher
        assert pub is not None
        assert handler._ConfigRuleHandler__metrics is pub

    def test_alerting_returns_same_instance(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        first = handler._alerting_service
        second = handler._alerting_service
        assert first is second

    def test_metrics_returns_same_instance(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        first = handler._metrics_publisher
        second = handler._metrics_publisher
        assert first is second

    def test_discovery_and_evaluator_are_eager(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        assert handler._discovery is not None
        assert handler._evaluator is not None


class TestSummaryCalculation:
    """Task 8.2: Single-pass summary with Counter."""

    def test_empty_results(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        summary = handler._build_summary([], {}, 100.0)
        assert summary["totalRecords"] == 0
        assert summary["compliant"] == 0
        assert summary["nonCompliant"] == 0
        assert summary["notApplicable"] == 0
        assert summary["insufficientData"] == 0

    def test_mixed_statuses(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        results = [
            _make_result(ComplianceStatus.COMPLIANT),
            _make_result(ComplianceStatus.COMPLIANT),
            _make_result(ComplianceStatus.NON_COMPLIANT),
            _make_result(ComplianceStatus.NOT_APPLICABLE),
            _make_result(ComplianceStatus.INSUFFICIENT_DATA),
        ]
        summary = handler._build_summary(results, {}, 50.0)
        assert summary["totalRecords"] == 5
        assert summary["compliant"] == 2
        assert summary["nonCompliant"] == 1
        assert summary["notApplicable"] == 1
        assert summary["insufficientData"] == 1

    def test_alert_summary_forwarded(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        alert = {"findings_created": 3, "notifications_sent": 2}
        summary = handler._build_summary([], alert, 10.0)
        assert summary["findingsCreated"] == 3
        assert summary["notificationsSent"] == 2

    def test_duration_rounded(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        summary = handler._build_summary([], {}, 123.456789)
        assert summary["durationMs"] == 123.46


class TestErrorSanitization:
    """Task 8.3: Error annotations must not contain raw exception messages."""

    def test_annotation_contains_exception_type_not_message(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        handler._evaluator = MagicMock()
        handler._evaluator.evaluate_record.side_effect = ValueError(
            "secret internal detail"
        )

        record = _make_record()
        results = handler._evaluate_with_isolation([record])

        assert len(results) == 1
        assert results[0].compliance_status == ComplianceStatus.INSUFFICIENT_DATA
        assert "ValueError" in results[0].annotation
        assert "secret internal detail" not in results[0].annotation

    def test_annotation_truncated_to_256_chars(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        handler._evaluator = MagicMock()
        # Create an exception with a very long type name via a dynamic class
        LongName = type("A" * 300, (Exception,), {})
        handler._evaluator.evaluate_record.side_effect = LongName("msg")

        record = _make_record()
        results = handler._evaluate_with_isolation([record])

        assert len(results[0].annotation) <= _MAX_ANNOTATION_LENGTH

    def test_successful_records_unaffected_by_failed_ones(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        handler._evaluator = MagicMock()

        good_result = _make_result(ComplianceStatus.COMPLIANT)
        handler._evaluator.evaluate_record.side_effect = [
            good_result,
            RuntimeError("boom"),
            good_result,
        ]

        records = [_make_record(), _make_record(), _make_record()]
        results = handler._evaluate_with_isolation(records)

        assert len(results) == 3
        assert results[0].compliance_status == ComplianceStatus.COMPLIANT
        assert results[1].compliance_status == ComplianceStatus.INSUFFICIENT_DATA
        assert results[2].compliance_status == ComplianceStatus.COMPLIANT


class TestDeterministicJitter:
    """Task 8.4: Deterministic jitter with injectable RNG."""

    def test_default_rng_is_random_instance(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        assert isinstance(handler._rng, random.Random)

    def test_injected_rng_used_for_backoff(self):
        mock_config = MagicMock()
        rng = random.Random(42)  # nosec B311
        handler = ConfigRuleHandler(config_client=mock_config, rng=rng)

        # Reset seed and compute expected delay
        rng_check = random.Random(42)  # nosec B311
        expected_jitter = rng_check.randint(0, handler.BASE_DELAY_MS // 2)
        expected_delay = min(
            handler.BASE_DELAY_MS + expected_jitter, handler.MAX_DELAY_MS
        )

        delay = handler._calculate_backoff_delay(0)
        assert delay == expected_delay

    def test_deterministic_seed_produces_repeatable_delays(self):
        mock_config = MagicMock()
        delays_a = []
        delays_b = []

        for seed_run, delays_list in [(42, delays_a), (42, delays_b)]:
            rng = random.Random(seed_run)  # nosec B311
            handler = ConfigRuleHandler(config_client=mock_config, rng=rng)
            for attempt in range(3):
                delays_list.append(handler._calculate_backoff_delay(attempt))

        assert delays_a == delays_b

    def test_backoff_delay_capped_at_max(self):
        mock_config = MagicMock()
        rng = random.Random(0)  # nosec B311
        handler = ConfigRuleHandler(config_client=mock_config, rng=rng)
        # Very high attempt to force large delay
        delay = handler._calculate_backoff_delay(20)
        assert delay <= handler.MAX_DELAY_MS


class TestRetryLogic:
    """Tests for _retry_with_backoff."""

    def test_succeeds_on_first_attempt(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config, rng=random.Random(0))  # nosec B311
        result = handler._retry_with_backoff(lambda: "ok", "test-op")
        assert result == "ok"

    @patch("src.handler.time.sleep")
    def test_retries_on_throttling(self, mock_sleep):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config, rng=random.Random(0))  # nosec B311

        call_count = 0

        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise _make_client_error("ThrottlingException")
            return "success"

        result = handler._retry_with_backoff(flaky, "test-op")
        assert result == "success"
        assert call_count == 3
        assert mock_sleep.call_count == 2

    def test_non_retryable_error_raises_immediately(self):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config, rng=random.Random(0))  # nosec B311

        with pytest.raises(ClientError) as exc_info:
            handler._retry_with_backoff(
                lambda: (_ for _ in ()).throw(
                    _make_client_error("AccessDeniedException")
                ),
                "test-op",
            )
        assert "AccessDeniedException" in str(exc_info.value)

    @patch("src.handler.time.sleep")
    def test_exhausted_retries_raises(self, mock_sleep):
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config, rng=random.Random(0))  # nosec B311

        with pytest.raises(ClientError):
            handler._retry_with_backoff(
                lambda: (_ for _ in ()).throw(
                    _make_client_error("ThrottlingException")
                ),
                "test-op",
            )


class TestAllExport:
    """Task 8.7: __all__ export list."""

    def test_all_contains_expected_names(self):
        from src import handler
        assert hasattr(handler, "__all__")
        assert "ConfigRuleHandler" in handler.__all__
        assert "lambda_handler" in handler.__all__
