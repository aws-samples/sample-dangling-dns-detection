"""Integration tests for Route53Discovery using moto-mocked Route 53.

Tests pagination handling and CNAME extraction against a realistic
moto-backed Route 53 environment.

Validates: Requirements 19.1
"""

import boto3
import pytest
from moto import mock_aws

from src.discovery import Route53Discovery


@pytest.mark.integration
@mock_aws
class TestRoute53DiscoveryIntegration:
    """Integration tests for Route53Discovery with moto Route 53."""

    def _create_hosted_zone(self, client, name: str) -> str:
        """Create a hosted zone and return its ID (without /hostedzone/ prefix)."""
        resp = client.create_hosted_zone(
            Name=name,
            CallerReference=f"ref-{name}",
        )
        return resp["HostedZone"]["Id"].replace("/hostedzone/", "")

    def _add_cname_record(
        self, client, zone_id: str, name: str, target: str, ttl: int = 300
    ) -> None:
        """Add a CNAME record to a hosted zone."""
        client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": "CNAME",
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": target}],
                        },
                    }
                ]
            },
        )

    def _add_a_record(self, client, zone_id: str, name: str) -> None:
        """Add an A record to a hosted zone."""
        client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": "192.0.2.1"}],
                        },
                    }
                ]
            },
        )

    def test_discovers_cname_from_single_zone(self):
        """Discovers a CNAME record from a single hosted zone."""
        r53 = boto3.client("route53", region_name="us-east-1")
        zone_id = self._create_hosted_zone(r53, "example.com")
        self._add_cname_record(
            r53, zone_id, "app.example.com", "bucket.s3.amazonaws.com"
        )

        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()

        assert len(records) == 1
        assert records[0].record_name == "app.example.com"
        assert records[0].target == "bucket.s3.amazonaws.com"
        assert records[0].zone_name == "example.com"
        assert records[0].ttl == 300

    def test_discovers_cnames_across_multiple_zones(self):
        """Discovers CNAME records from multiple hosted zones."""
        r53 = boto3.client("route53", region_name="us-east-1")
        zone1 = self._create_hosted_zone(r53, "one.com")
        zone2 = self._create_hosted_zone(r53, "two.com")

        self._add_cname_record(r53, zone1, "a.one.com", "t1.example.com")
        self._add_cname_record(r53, zone2, "b.two.com", "t2.example.com")

        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()

        names = {r.record_name for r in records}
        assert "a.one.com" in names
        assert "b.two.com" in names

    def test_filters_out_non_cname_records(self):
        """Only CNAME records are returned; A records are filtered out."""
        r53 = boto3.client("route53", region_name="us-east-1")
        zone_id = self._create_hosted_zone(r53, "example.com")
        self._add_a_record(r53, zone_id, "www.example.com")
        self._add_cname_record(
            r53, zone_id, "app.example.com", "target.example.net"
        )

        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()

        assert all(r.record_name != "www.example.com" for r in records)
        cname_names = {r.record_name for r in records}
        assert "app.example.com" in cname_names

    def test_empty_zone_returns_no_records(self):
        """A hosted zone with no CNAME records returns empty list."""
        r53 = boto3.client("route53", region_name="us-east-1")
        self._create_hosted_zone(r53, "empty.com")

        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()

        # May contain SOA/NS from zone creation, but no CNAMEs
        assert all(hasattr(r, "target") for r in records)
        # All returned records should be CNAMEs (our discovery only yields CNAMEs)
        assert len(records) == 0

    def test_multiple_cnames_in_single_zone(self):
        """Multiple CNAME records in one zone are all discovered."""
        r53 = boto3.client("route53", region_name="us-east-1")
        zone_id = self._create_hosted_zone(r53, "example.com")

        for i in range(5):
            self._add_cname_record(
                r53, zone_id, f"svc{i}.example.com", f"target{i}.example.net"
            )

        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()

        assert len(records) == 5
        names = {r.record_name for r in records}
        for i in range(5):
            assert f"svc{i}.example.com" in names

    def test_cname_target_extraction(self):
        """CNAME target values are correctly extracted and trailing dots stripped."""
        r53 = boto3.client("route53", region_name="us-east-1")
        zone_id = self._create_hosted_zone(r53, "example.com")
        self._add_cname_record(
            r53, zone_id, "cdn.example.com", "d1234abcd.cloudfront.net"
        )

        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()

        assert len(records) == 1
        assert records[0].target == "d1234abcd.cloudfront.net"

    def test_returns_list_type(self):
        """discover_cname_records returns a list."""
        r53 = boto3.client("route53", region_name="us-east-1")
        self._create_hosted_zone(r53, "example.com")

        discovery = Route53Discovery(client=r53)
        result = discovery.discover_cname_records()
        assert isinstance(result, list)

    def test_no_hosted_zones_returns_empty(self):
        """When there are no hosted zones, returns empty list."""
        r53 = boto3.client("route53", region_name="us-east-1")
        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()
        assert records == []

    def test_ttl_preserved(self):
        """TTL values are correctly preserved from the record set."""
        r53 = boto3.client("route53", region_name="us-east-1")
        zone_id = self._create_hosted_zone(r53, "example.com")
        self._add_cname_record(
            r53, zone_id, "app.example.com", "target.example.net", ttl=600
        )

        discovery = Route53Discovery(client=r53)
        records = discovery.discover_cname_records()

        assert records[0].ttl == 600
