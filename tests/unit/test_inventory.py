"""
Unit tests for the InventoryQuery class.

Tests cache behavior, query construction, validation rejection,
and identifier extraction.

Validates: Requirements 1.1, 1.2, 1.3, 3.1, 17.2
"""

import json
from unittest.mock import MagicMock

import pytest

from src.inventory import InventoryQuery
from src.models import ResourceType


class TestInventoryQueryCache:
    """Tests for InventoryQuery caching behavior."""

    def test_cache_hit_avoids_second_api_call(self):
        """Querying the same resource type twice should use the cache."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {
            "Results": [json.dumps({"resourceName": "my-bucket", "resourceId": "my-bucket"})],
        }
        iq = InventoryQuery(client=mock_client)

        first = iq.get_s3_buckets()
        second = iq.get_s3_buckets()

        assert first == second
        assert mock_client.select_resource_config.call_count == 1

    def test_different_resource_types_are_cached_independently(self):
        """Each resource type should have its own cache entry."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {
            "Results": [json.dumps({"resourceId": "d123abc"})],
        }
        iq = InventoryQuery(client=mock_client)

        iq.get_s3_buckets()
        iq.get_cloudfront_distributions()

        assert mock_client.select_resource_config.call_count == 2

    def test_cache_stores_lowercase_identifiers(self):
        """Cached identifiers should be lowercased for case-insensitive matching."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {
            "Results": [json.dumps({"resourceName": "MyBucket", "resourceId": "MyBucket"})],
        }
        iq = InventoryQuery(client=mock_client)

        result = iq.get_s3_buckets()
        assert "mybucket" in result


class TestInventoryQueryValidation:
    """Tests for query parameter validation (Requirements 1.1, 1.2, 1.3)."""

    def test_valid_resource_type_accepted(self):
        """Known Config resource types should be accepted without error."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {"Results": []}
        iq = InventoryQuery(client=mock_client)

        # Should not raise — these are valid mapping values
        result = iq._query_resources("AWS::S3::Bucket", ResourceType.S3_BUCKET)
        assert isinstance(result, set)

    def test_invalid_resource_type_raises_value_error(self):
        """Unknown Config resource types should raise ValueError."""
        mock_client = MagicMock()
        iq = InventoryQuery(client=mock_client)

        with pytest.raises(ValueError, match="Invalid config resource type"):
            iq._query_resources("AWS::EC2::Instance", ResourceType.S3_BUCKET)

    def test_empty_string_resource_type_raises_value_error(self):
        """Empty string as resource type should raise ValueError."""
        mock_client = MagicMock()
        iq = InventoryQuery(client=mock_client)

        with pytest.raises(ValueError, match="Invalid config resource type"):
            iq._query_resources("", ResourceType.S3_BUCKET)

    def test_all_valid_types_accepted(self):
        """All values in RESOURCE_TYPE_QUERIES should be accepted."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {"Results": []}
        iq = InventoryQuery(client=mock_client)

        for rt, config_type in InventoryQuery.RESOURCE_TYPE_QUERIES.items():
            result = iq._query_resources(config_type, rt)
            assert isinstance(result, set)


class TestInventoryQueryConstruction:
    """Tests for query construction and execution."""

    def test_query_contains_resource_type(self):
        """The SQL expression should contain the config resource type."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {"Results": []}
        iq = InventoryQuery(client=mock_client)

        iq._query_resources("AWS::S3::Bucket", ResourceType.S3_BUCKET)

        call_kwargs = mock_client.select_resource_config.call_args[1]
        assert "AWS::S3::Bucket" in call_kwargs["Expression"]

    def test_pagination_follows_next_token(self):
        """Query should follow NextToken for paginated results."""
        mock_client = MagicMock()
        mock_client.select_resource_config.side_effect = [
            {
                "Results": [json.dumps({"resourceName": "bucket-1", "resourceId": "bucket-1"})],
                "NextToken": "token-1",
            },
            {
                "Results": [json.dumps({"resourceName": "bucket-2", "resourceId": "bucket-2"})],
            },
        ]
        iq = InventoryQuery(client=mock_client)

        result = iq._query_resources("AWS::S3::Bucket", ResourceType.S3_BUCKET)
        assert "bucket-1" in result
        assert "bucket-2" in result
        assert mock_client.select_resource_config.call_count == 2


class TestInventoryQueryIdentifierExtraction:
    """Tests for _extract_identifier across resource types."""

    def setup_method(self):
        self.iq = InventoryQuery(client=MagicMock())

    def test_s3_extracts_resource_name(self):
        """S3 should prefer resourceName."""
        result_json = json.dumps({"resourceName": "my-bucket", "resourceId": "my-bucket-id"})
        assert self.iq._extract_identifier(result_json, ResourceType.S3_BUCKET) == "my-bucket"

    def test_s3_falls_back_to_resource_id(self):
        """S3 should fall back to resourceId when resourceName is missing."""
        result_json = json.dumps({"resourceId": "my-bucket-id"})
        assert self.iq._extract_identifier(result_json, ResourceType.S3_BUCKET) == "my-bucket-id"

    def test_cloudfront_extracts_resource_id(self):
        """CloudFront should extract resourceId."""
        result_json = json.dumps({"resourceId": "EDFDVBD6EXAMPLE"})
        assert self.iq._extract_identifier(result_json, ResourceType.CLOUDFRONT_DISTRIBUTION) == "EDFDVBD6EXAMPLE"

    def test_elasticbeanstalk_extracts_resource_name(self):
        """Elastic Beanstalk should prefer resourceName."""
        result_json = json.dumps({"resourceName": "my-env", "resourceId": "e-abc123"})
        assert self.iq._extract_identifier(result_json, ResourceType.ELASTICBEANSTALK_ENVIRONMENT) == "my-env"

    def test_invalid_json_returns_none(self):
        """Invalid JSON should return None without raising."""
        assert self.iq._extract_identifier("not-json", ResourceType.S3_BUCKET) is None

    def test_empty_json_object_returns_none(self):
        """Empty JSON object should return None for S3 (no resourceName or resourceId)."""
        assert self.iq._extract_identifier("{}", ResourceType.S3_BUCKET) is None


class TestInventoryQueryResourceExists:
    """Tests for the resource_exists method."""

    def test_existing_resource_returns_true(self):
        """resource_exists should return True for a known resource."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {
            "Results": [json.dumps({"resourceName": "my-bucket", "resourceId": "my-bucket"})],
        }
        iq = InventoryQuery(client=mock_client)

        assert iq.resource_exists(ResourceType.S3_BUCKET, "my-bucket") is True

    def test_missing_resource_returns_false(self):
        """resource_exists should return False for an unknown resource."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {
            "Results": [json.dumps({"resourceName": "other-bucket", "resourceId": "other-bucket"})],
        }
        iq = InventoryQuery(client=mock_client)

        assert iq.resource_exists(ResourceType.S3_BUCKET, "missing-bucket") is False

    def test_case_insensitive_lookup(self):
        """resource_exists should match case-insensitively."""
        mock_client = MagicMock()
        mock_client.select_resource_config.return_value = {
            "Results": [json.dumps({"resourceName": "MyBucket", "resourceId": "MyBucket"})],
        }
        iq = InventoryQuery(client=mock_client)

        assert iq.resource_exists(ResourceType.S3_BUCKET, "MYBUCKET") is True
