"""
Property-based tests for ConfigRuleHandler.

Feature: code-quality-optimization, Properties 2 and 3

Validates: Requirements 2.1, 2.3, 8.1, 8.2
"""

import random
from collections import Counter
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.handler import ConfigRuleHandler, _MAX_ANNOTATION_LENGTH
from src.models import (
    CnameRecord,
    ComplianceStatus,
    EvaluationResult,
)


def _make_record() -> CnameRecord:
    return CnameRecord(
        zone_id="Z123",
        zone_name="example.com",
        record_name="app.example.com",
        target="mybucket.s3.amazonaws.com",
        ttl=300,
    )


def _make_result(status: ComplianceStatus) -> EvaluationResult:
    return EvaluationResult(
        record=_make_record(),
        resource_type=None,
        compliance_status=status,
        annotation="test",
    )


@pytest.mark.property
class TestErrorAnnotationSanitizationAndBounds:
    """Property 2: Error annotation sanitization and bounds.

    For any exception message string of arbitrary content and length,
    when an evaluation failure occurs, the resulting annotation SHALL NOT
    contain the raw exception message text AND SHALL be at most 256
    characters in length.

    **Validates: Requirements 2.1, 2.3**
    """

    @given(error_message=st.text(min_size=1, max_size=1000))
    def test_annotation_does_not_contain_raw_message_and_is_bounded(
        self, error_message: str
    ) -> None:
        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        handler._evaluator = MagicMock()
        handler._evaluator.evaluate_record.side_effect = RuntimeError(error_message)

        record = _make_record()
        results = handler._evaluate_with_isolation([record])

        assert len(results) == 1
        annotation = results[0].annotation

        # The annotation format is "Evaluation failed: <ExceptionType>".
        # For messages long enough to be meaningful (longer than the
        # exception type name), verify the raw message is absent.
        # Short messages (e.g. " ", "e") may trivially appear as
        # substrings of the fixed annotation text, so we only check
        # the non-trivial case.
        exception_type_name = "RuntimeError"
        if len(error_message) > len(exception_type_name):
            assert error_message not in annotation

        # Annotation must be within the 256-char bound
        assert len(annotation) <= _MAX_ANNOTATION_LENGTH


@pytest.mark.property
class TestSinglePassSummaryCorrectness:
    """Property 3: Single-pass summary correctness.

    For any list of EvaluationResult objects with arbitrary compliance
    statuses, the _build_summary method SHALL produce counts where
    compliant + nonCompliant + notApplicable + insufficientData == totalRecords
    and each count matches the actual number of results with that status.

    **Validates: Requirements 8.1, 8.2**
    """

    @given(statuses=st.lists(st.sampled_from(list(ComplianceStatus)), max_size=200))
    def test_summary_counts_are_correct_and_sum_to_total(
        self, statuses: list[ComplianceStatus]
    ) -> None:
        results = [_make_result(s) for s in statuses]
        expected = Counter(statuses)

        mock_config = MagicMock()
        handler = ConfigRuleHandler(config_client=mock_config)
        summary = handler._build_summary(results, {}, 0.0)

        # Individual counts match
        assert summary["compliant"] == expected.get(ComplianceStatus.COMPLIANT, 0)
        assert summary["nonCompliant"] == expected.get(ComplianceStatus.NON_COMPLIANT, 0)
        assert summary["notApplicable"] == expected.get(ComplianceStatus.NOT_APPLICABLE, 0)
        assert summary["insufficientData"] == expected.get(ComplianceStatus.INSUFFICIENT_DATA, 0)

        # Sum equals total
        total = (
            summary["compliant"]
            + summary["nonCompliant"]
            + summary["notApplicable"]
            + summary["insufficientData"]
        )
        assert total == summary["totalRecords"]
        assert summary["totalRecords"] == len(results)
