"""Integration tests for InventoryQuery using moto-mocked AWS Config.

moto's Config select_resource_config does not return results for resources
created via other moto-mocked services, so we mock the Config client's
select_resource_config response while still validating the full integration
flow including caching, pagination, and identifier extraction.

Validates: Requirements 19.2
"""

import json
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from src.inventory import InventoryQuery
from src.models import ResourceType


@pytest.mark.integration
class TestInventoryQueryIntegration:
    """Integration tests for InventoryQuery.

    Since moto's Config select_resource_config doesn't populate results
    from resources created via other services, we use a mock Config client
    that returns realistic responses to validate the full integration flow.
    """

    def _make_config_client(self, results_by_call=None):
        """Create a mock Config client with realistic select_resource_config responses.

        Args:
            results_by_call: List of response dicts for sequential calls.
                Each dict has 'Results' (list of JSON strings) and optional 'NextToken'.
        """
        client = MagicMock()
        if results_by_call is None:
            client.select_resource_config.return_value = {"Results": []}
        else:
            client.select_resource_config.side_effect = results_by_call
        return client

    def test_query_execution_returns_resources(self):
        """InventoryQuery correctly processes Config query results."""
        results = [
            json.dumps({"resourceName": "my-bucket", "resourceId": "my-bucket"}),
            json.dumps({"resourceName": "other-bucket", "resourceId": "other-bucket"}),
        ]
        client = self._make_config_client([{"Results": results}])
        iq = InventoryQuery(client=client)

        buckets = iq.get_s3_buckets()

        assert buckets is not None
        assert "my-bucket" in buckets
        assert "other-bucket" in buckets

    def test_caching_avoids_repeated_queries(self):
        """Second call for same resource type uses cache, not API."""
        results = [
            json.dumps({"resourceName": "bucket-1", "resourceId": "bucket-1"}),
        ]
        client = self._make_config_client([{"Results": results}])
        iq = InventoryQuery(client=client)

        first = iq.get_s3_buckets()
        second = iq.get_s3_buckets()

        assert first == second
        assert client.select_resource_config.call_count == 1

    def test_different_resource_types_cached_independently(self):
        """Each resource type has its own cache entry."""
        s3_results = [json.dumps({"resourceName": "bucket-1", "resourceId": "bucket-1"})]
        cf_results = [json.dumps({"resourceId": "EDFDVBD6EXAMPLE"})]
        client = self._make_config_client([
            {"Results": s3_results},
            {"Results": cf_results},
        ])
        iq = InventoryQuery(client=client)

        buckets = iq.get_s3_buckets()
        distributions = iq.get_cloudfront_distributions()

        assert "bucket-1" in buckets
        assert "edfdvbd6example" in distributions
        assert client.select_resource_config.call_count == 2

    def test_pagination_follows_next_token(self):
        """Query follows NextToken for paginated Config results."""
        client = self._make_config_client([
            {
                "Results": [json.dumps({"resourceName": "bucket-1", "resourceId": "bucket-1"})],
                "NextToken": "page-2-token",
            },
            {
                "Results": [json.dumps({"resourceName": "bucket-2", "resourceId": "bucket-2"})],
            },
        ])
        iq = InventoryQuery(client=client)

        buckets = iq.get_s3_buckets()

        assert "bucket-1" in buckets
        assert "bucket-2" in buckets
        assert client.select_resource_config.call_count == 2

    def test_resource_exists_returns_true_for_known_resource(self):
        """resource_exists returns True for a resource in the inventory."""
        results = [json.dumps({"resourceName": "my-bucket", "resourceId": "my-bucket"})]
        client = self._make_config_client([{"Results": results}])
        iq = InventoryQuery(client=client)

        assert iq.resource_exists(ResourceType.S3_BUCKET, "my-bucket") is True

    def test_resource_exists_returns_false_for_unknown_resource(self):
        """resource_exists returns False for a resource not in the inventory."""
        results = [json.dumps({"resourceName": "other-bucket", "resourceId": "other-bucket"})]
        client = self._make_config_client([{"Results": results}])
        iq = InventoryQuery(client=client)

        assert iq.resource_exists(ResourceType.S3_BUCKET, "missing-bucket") is False

    def test_case_insensitive_resource_lookup(self):
        """resource_exists performs case-insensitive matching."""
        results = [json.dumps({"resourceName": "MyBucket", "resourceId": "MyBucket"})]
        client = self._make_config_client([{"Results": results}])
        iq = InventoryQuery(client=client)

        assert iq.resource_exists(ResourceType.S3_BUCKET, "MYBUCKET") is True
        assert iq.resource_exists(ResourceType.S3_BUCKET, "mybucket") is True

    def test_cloudfront_identifier_extraction(self):
        """CloudFront distribution IDs are correctly extracted."""
        results = [json.dumps({"resourceId": "E1234ABCDEF"})]
        client = self._make_config_client([{"Results": results}])
        iq = InventoryQuery(client=client)

        distributions = iq.get_cloudfront_distributions()
        assert "e1234abcdef" in distributions

    def test_elasticbeanstalk_identifier_extraction(self):
        """Elastic Beanstalk environment names are correctly extracted."""
        results = [json.dumps({"resourceName": "my-env", "resourceId": "e-abc123"})]
        client = self._make_config_client([{"Results": results}])
        iq = InventoryQuery(client=client)

        envs = iq.get_elasticbeanstalk_environments()
        assert "my-env" in envs

    def test_invalid_resource_type_raises_value_error(self):
        """Passing an invalid config resource type raises ValueError."""
        client = self._make_config_client()
        iq = InventoryQuery(client=client)

        with pytest.raises(ValueError, match="Invalid config resource type"):
            iq._query_resources("AWS::EC2::Instance", ResourceType.S3_BUCKET)

    def test_empty_results_returns_empty_set(self):
        """Empty Config results return an empty set."""
        client = self._make_config_client([{"Results": []}])
        iq = InventoryQuery(client=client)

        buckets = iq.get_s3_buckets()
        assert buckets == set()
