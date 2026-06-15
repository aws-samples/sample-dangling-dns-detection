"""Property-based tests for MetricsPublisher._calculate_metrics.

Property 10: Metrics calculation correctness
Verify total == len(results), by_status counts sum to total,
by_resource_type counts are consistent subsets.

Validates: Requirements 22.1, 22.2
"""

from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from src.metrics import MetricsPublisher
from src.models import (
    CnameRecord,
    ComplianceStatus,
    EvaluationResult,
    ResourceType,
)

# --- Strategies ---

_compliance_statuses = st.sampled_from(list(ComplianceStatus))
_resource_types = st.sampled_from([None] + list(ResourceType))

_cname_record = st.builds(
    CnameRecord,
    zone_id=st.just("Z123"),
    zone_name=st.just("example.com"),
    record_name=st.just("app.example.com"),
    target=st.just("mybucket.s3.amazonaws.com"),
    ttl=st.just(300),
)

_evaluation_result = st.builds(
    EvaluationResult,
    record=_cname_record,
    resource_type=_resource_types,
    compliance_status=_compliance_statuses,
    annotation=st.just("test"),
)

_results_list = st.lists(_evaluation_result, min_size=0, max_size=50)


# Feature: code-quality-optimization, Property 10: Metrics calculation correctness


@given(results=_results_list)
@settings(max_examples=100)
def test_total_equals_len_results(results):
    """**Validates: Requirements 22.1, 22.2**

    total must equal the number of input results.
    """
    publisher = MetricsPublisher(client=MagicMock())
    metrics = publisher._calculate_metrics(results)
    assert metrics["total"] == len(results)


@given(results=_results_list)
@settings(max_examples=100)
def test_by_status_counts_sum_to_total(results):
    """**Validates: Requirements 22.1, 22.2**

    The sum of all by_status counts must equal total.
    """
    publisher = MetricsPublisher(client=MagicMock())
    metrics = publisher._calculate_metrics(results)
    assert sum(metrics["by_status"].values()) == metrics["total"]


@given(results=_results_list)
@settings(max_examples=100)
def test_by_resource_type_counts_are_consistent_subsets(results):
    """**Validates: Requirements 22.1, 22.2**

    For each resource type, the sum of its status counts must not exceed
    the corresponding by_status counts, and the total of all resource-type
    counts must not exceed total (since some results have resource_type=None).
    """
    publisher = MetricsPublisher(client=MagicMock())
    metrics = publisher._calculate_metrics(results)

    resource_type_total = 0
    for rt, status_counter in metrics["by_resource_type"].items():
        for status, count in status_counter.items():
            # Each resource-type/status count must be <= the aggregate status count
            assert count <= metrics["by_status"][status]
        resource_type_total += sum(status_counter.values())

    # Total across all resource types <= total (some results have None resource_type)
    assert resource_type_total <= metrics["total"]
