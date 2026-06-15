"""Unit tests for Route53Discovery module.

Tests pagination handling, CNAME extraction, and list construction.
Validates: Requirements 5.1, 5.2, 9.3, 17.1
"""

from unittest.mock import MagicMock, patch

import pytest

from src.discovery import Route53Discovery
from src.models import CnameRecord


class TestRoute53Discovery:
    """Tests for Route53Discovery class."""

    def _make_zone(self, zone_id: str, name: str) -> dict:
        return {"Id": f"/hostedzone/{zone_id}", "Name": f"{name}."}

    def _make_cname_record_set(
        self, name: str, target: str, ttl: int = 300
    ) -> dict:
        return {
            "Name": f"{name}.",
            "Type": "CNAME",
            "TTL": ttl,
            "ResourceRecords": [{"Value": f"{target}."}],
        }

    def _make_a_record_set(self, name: str) -> dict:
        return {
            "Name": f"{name}.",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [{"Value": "192.0.2.1"}],
        }

    def _build_mock_client(self, zones_pages, records_by_zone):
        """Build a mock Route53 client with paginator support.

        Args:
            zones_pages: list of lists of zone dicts (each inner list = one page)
            records_by_zone: dict mapping zone_id -> list of lists of record sets (pages)
        """
        client = MagicMock()

        def get_paginator(operation):
            if operation == "list_hosted_zones":
                paginator = MagicMock()
                paginator.paginate.return_value = [
                    {"HostedZones": page} for page in zones_pages
                ]
                return paginator
            elif operation == "list_resource_record_sets":
                paginator = MagicMock()

                def paginate_records(**kwargs):
                    zone_id = kwargs["HostedZoneId"]
                    pages = records_by_zone.get(zone_id, [[]])
                    return [{"ResourceRecordSets": page} for page in pages]

                paginator.paginate.side_effect = paginate_records
                return paginator
            raise ValueError(f"Unexpected paginator: {operation}")

        client.get_paginator.side_effect = get_paginator
        return client

    def test_empty_zones(self):
        """No hosted zones returns empty list."""
        client = self._build_mock_client(zones_pages=[[]], records_by_zone={})
        discovery = Route53Discovery(client=client)
        assert discovery.discover_cname_records() == []

    def test_single_zone_single_cname(self):
        """Single zone with one CNAME record."""
        zone = self._make_zone("Z123", "example.com")
        cname = self._make_cname_record_set(
            "app.example.com", "bucket.s3.amazonaws.com", ttl=300
        )
        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z123": [[cname]]},
        )
        discovery = Route53Discovery(client=client)
        results = discovery.discover_cname_records()

        assert len(results) == 1
        assert results[0].zone_id == "Z123"
        assert results[0].zone_name == "example.com"
        assert results[0].record_name == "app.example.com"
        assert results[0].target == "bucket.s3.amazonaws.com"
        assert results[0].ttl == 300

    def test_non_cname_records_skipped(self):
        """A and other record types are filtered out."""
        zone = self._make_zone("Z123", "example.com")
        a_record = self._make_a_record_set("www.example.com")
        cname = self._make_cname_record_set(
            "app.example.com", "target.example.net"
        )
        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z123": [[a_record, cname]]},
        )
        discovery = Route53Discovery(client=client)
        results = discovery.discover_cname_records()

        assert len(results) == 1
        assert results[0].record_name == "app.example.com"

    def test_alias_cname_skipped(self):
        """CNAME with empty ResourceRecords (alias) is skipped."""
        zone = self._make_zone("Z123", "example.com")
        alias_cname = {
            "Name": "alias.example.com.",
            "Type": "CNAME",
            "TTL": 300,
            "ResourceRecords": [],
        }
        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z123": [[alias_cname]]},
        )
        discovery = Route53Discovery(client=client)
        assert discovery.discover_cname_records() == []

    def test_empty_target_skipped(self):
        """CNAME with empty Value is skipped."""
        zone = self._make_zone("Z123", "example.com")
        empty_target = {
            "Name": "empty.example.com.",
            "Type": "CNAME",
            "TTL": 300,
            "ResourceRecords": [{"Value": ""}],
        }
        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z123": [[empty_target]]},
        )
        discovery = Route53Discovery(client=client)
        assert discovery.discover_cname_records() == []

    def test_pagination_multiple_zone_pages(self):
        """Zones spread across multiple pages are all discovered."""
        zone1 = self._make_zone("Z1", "one.com")
        zone2 = self._make_zone("Z2", "two.com")
        cname1 = self._make_cname_record_set("a.one.com", "t1.example.com")
        cname2 = self._make_cname_record_set("b.two.com", "t2.example.com")

        client = self._build_mock_client(
            zones_pages=[[zone1], [zone2]],
            records_by_zone={
                "Z1": [[cname1]],
                "Z2": [[cname2]],
            },
        )
        discovery = Route53Discovery(client=client)
        results = discovery.discover_cname_records()

        assert len(results) == 2
        names = {r.record_name for r in results}
        assert names == {"a.one.com", "b.two.com"}

    def test_pagination_multiple_record_pages(self):
        """Records spread across multiple pages within a zone."""
        zone = self._make_zone("Z1", "example.com")
        cname1 = self._make_cname_record_set("a.example.com", "t1.example.com")
        cname2 = self._make_cname_record_set("b.example.com", "t2.example.com")

        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z1": [[cname1], [cname2]]},
        )
        discovery = Route53Discovery(client=client)
        results = discovery.discover_cname_records()

        assert len(results) == 2
        names = {r.record_name for r in results}
        assert names == {"a.example.com", "b.example.com"}

    def test_trailing_dots_stripped(self):
        """Trailing dots on zone name, record name, and target are stripped."""
        zone = self._make_zone("Z1", "example.com")
        cname = self._make_cname_record_set(
            "app.example.com", "bucket.s3.amazonaws.com"
        )
        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z1": [[cname]]},
        )
        discovery = Route53Discovery(client=client)
        results = discovery.discover_cname_records()

        assert results[0].zone_name == "example.com"
        assert results[0].record_name == "app.example.com"
        assert results[0].target == "bucket.s3.amazonaws.com"

    def test_returns_list_type(self):
        """discover_cname_records returns a list (not generator or other iterable)."""
        client = self._build_mock_client(zones_pages=[[]], records_by_zone={})
        discovery = Route53Discovery(client=client)
        result = discovery.discover_cname_records()
        assert isinstance(result, list)

    def test_multiple_cnames_in_single_zone(self):
        """Multiple CNAME records in a single zone are all returned."""
        zone = self._make_zone("Z1", "example.com")
        cnames = [
            self._make_cname_record_set(f"svc{i}.example.com", f"t{i}.example.net")
            for i in range(5)
        ]
        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z1": [cnames]},
        )
        discovery = Route53Discovery(client=client)
        results = discovery.discover_cname_records()
        assert len(results) == 5

    def test_default_ttl_zero(self):
        """When TTL is missing from record set, defaults to 0."""
        zone = self._make_zone("Z1", "example.com")
        record_set = {
            "Name": "app.example.com.",
            "Type": "CNAME",
            "ResourceRecords": [{"Value": "target.example.com."}],
        }
        client = self._build_mock_client(
            zones_pages=[[zone]],
            records_by_zone={"Z1": [[record_set]]},
        )
        discovery = Route53Discovery(client=client)
        results = discovery.discover_cname_records()
        assert results[0].ttl == 0


class TestRoute53DiscoveryAllExport:
    """Tests for __all__ export list."""

    def test_all_contains_route53discovery(self):
        from src import discovery
        assert hasattr(discovery, "__all__")
        assert "Route53Discovery" in discovery.__all__

    def test_standalone_function_removed(self):
        """The module-level discover_cname_records function should not exist."""
        from src import discovery
        # Only the class method should exist, not a module-level function
        assert not hasattr(discovery, "discover_cname_records") or callable(
            getattr(discovery.Route53Discovery, "discover_cname_records", None)
        )
        # More precise: check there's no module-level function with that name
        import types
        module_attrs = {
            name
            for name, val in vars(discovery).items()
            if isinstance(val, types.FunctionType)
        }
        assert "discover_cname_records" not in module_attrs
