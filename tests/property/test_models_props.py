"""
Property-based tests for CnameRecord construction validation.

Feature: code-quality-optimization, Property 4: CnameRecord construction validation

Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5
"""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from src.models import CnameRecord


# Strategy for non-empty strings (valid string fields)
non_empty_strings = st.text(min_size=1)

# Strategy for valid CnameRecord construction
valid_zone_id = st.text(min_size=1)
valid_zone_name = st.text(min_size=1)
valid_record_name = st.text(min_size=1)
valid_target = st.text(min_size=1)
valid_ttl = st.integers(min_value=0)


@pytest.mark.property
class TestCnameRecordConstructionValidation:
    """Property 4: CnameRecord construction validation.

    For any combination of field values, if zone_id is empty, record_name is
    empty, target is empty, or ttl is negative, constructing a CnameRecord
    SHALL raise a ValueError. For any combination where all fields are valid
    (non-empty strings and non-negative integer ttl), construction SHALL succeed.

    **Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5**
    """

    @given(
        zone_id=valid_zone_id,
        zone_name=valid_zone_name,
        record_name=valid_record_name,
        target=valid_target,
        ttl=valid_ttl,
    )
    def test_valid_inputs_succeed(
        self, zone_id: str, zone_name: str, record_name: str, target: str, ttl: int
    ) -> None:
        """Valid non-empty strings and non-negative ttl always construct successfully."""
        record = CnameRecord(
            zone_id=zone_id,
            zone_name=zone_name,
            record_name=record_name,
            target=target,
            ttl=ttl,
        )
        assert record.zone_id == zone_id
        assert record.zone_name == zone_name
        assert record.record_name == record_name
        assert record.target == target
        assert record.ttl == ttl

    @given(
        zone_name=st.text(),
        record_name=non_empty_strings,
        target=non_empty_strings,
        ttl=valid_ttl,
    )
    def test_empty_zone_id_raises(
        self, zone_name: str, record_name: str, target: str, ttl: int
    ) -> None:
        """Empty zone_id always raises ValueError."""
        with pytest.raises(ValueError, match="zone_id"):
            CnameRecord(
                zone_id="",
                zone_name=zone_name,
                record_name=record_name,
                target=target,
                ttl=ttl,
            )

    @given(
        zone_id=non_empty_strings,
        zone_name=st.text(),
        target=non_empty_strings,
        ttl=valid_ttl,
    )
    def test_empty_record_name_raises(
        self, zone_id: str, zone_name: str, target: str, ttl: int
    ) -> None:
        """Empty record_name always raises ValueError."""
        with pytest.raises(ValueError, match="record_name"):
            CnameRecord(
                zone_id=zone_id,
                zone_name=zone_name,
                record_name="",
                target=target,
                ttl=ttl,
            )

    @given(
        zone_id=non_empty_strings,
        zone_name=st.text(),
        record_name=non_empty_strings,
        ttl=valid_ttl,
    )
    def test_empty_target_raises(
        self, zone_id: str, zone_name: str, record_name: str, ttl: int
    ) -> None:
        """Empty target always raises ValueError."""
        with pytest.raises(ValueError, match="target"):
            CnameRecord(
                zone_id=zone_id,
                zone_name=zone_name,
                record_name=record_name,
                target="",
                ttl=ttl,
            )

    @given(
        zone_id=non_empty_strings,
        zone_name=st.text(),
        record_name=non_empty_strings,
        target=non_empty_strings,
        ttl=st.integers(max_value=-1),
    )
    def test_negative_ttl_raises(
        self, zone_id: str, zone_name: str, record_name: str, target: str, ttl: int
    ) -> None:
        """Negative ttl always raises ValueError."""
        with pytest.raises(ValueError, match="ttl"):
            CnameRecord(
                zone_id=zone_id,
                zone_name=zone_name,
                record_name=record_name,
                target=target,
                ttl=ttl,
            )
