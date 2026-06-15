"""
Property-based tests for InventoryQuery Config query type validation.

Feature: code-quality-optimization, Property 1: Config query type validation

Validates: Requirements 1.1, 1.2, 1.3
"""

from unittest.mock import MagicMock

import pytest
from hypothesis import given, assume
from hypothesis import strategies as st

from src.inventory import InventoryQuery
from src.models import ResourceType


# Valid Config resource type strings from the mapping
VALID_CONFIG_TYPES = list(InventoryQuery.RESOURCE_TYPE_QUERIES.values())


@pytest.mark.property
class TestConfigQueryTypeValidation:
    """Property 1: Config query type validation.

    For any string value passed as config_resource_type to
    InventoryQuery._query_resources, if the value is not present in the
    RESOURCE_TYPE_QUERIES mapping values, the method SHALL raise a ValueError.
    If the value IS present in the mapping, the method SHALL proceed without error.

    **Validates: Requirements 1.1, 1.2, 1.3**
    """

    @given(invalid_type=st.text())
    def test_invalid_types_raise_value_error(self, invalid_type: str) -> None:
        """Any string not in RESOURCE_TYPE_QUERIES values must raise ValueError."""
        assume(invalid_type not in VALID_CONFIG_TYPES)

        mock_client = MagicMock()
        iq = InventoryQuery(client=mock_client)

        with pytest.raises(ValueError, match="Invalid config resource type"):
            iq._query_resources(invalid_type, ResourceType.S3_BUCKET)

    @given(valid_type=st.sampled_from(VALID_CONFIG_TYPES))
    def test_valid_types_do_not_raise(self, valid_type: str) -> None:
        """Any string in RESOURCE_TYPE_QUERIES values must not raise."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {"Results": []}
        iq = InventoryQuery(client=mock_client)

        # Pick a matching ResourceType for the valid_type
        resource_type = next(
            rt for rt, ct in InventoryQuery.RESOURCE_TYPE_QUERIES.items()
            if ct == valid_type
        )

        # Should not raise
        result = iq._query_resources(valid_type, resource_type)
        assert isinstance(result, set)
